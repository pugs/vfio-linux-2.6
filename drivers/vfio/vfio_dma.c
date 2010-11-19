/*
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Portions derived from drivers/uio/uio.c:
 * Copyright(C) 2005, Benedikt Spranger <b.spranger@linutronix.de>
 * Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2006, Hans J. Koch <hjk@linutronix.de>
 * Copyright(C) 2006, Greg Kroah-Hartman <greg@kroah.com>
 *
 * Portions derived from drivers/uio/uio_pci_generic.c:
 * Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 */

/*
 * This code handles mapping and unmapping of user data buffers
 * into DMA'ble space using the IOMMU
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/iommu.h>
#include <linux/uiommu.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/vfio.h>

struct vwork {
	struct mm_struct *mm;
	int		npage;
	struct work_struct work;
};

/* delayed decrement for locked_vm */
static void vfio_lock_acct_bg(struct work_struct *work)
{
	struct vwork *vwork = container_of(work, struct vwork, work);
	struct mm_struct *mm;

	mm = vwork->mm;
	down_write(&mm->mmap_sem);
	mm->locked_vm += vwork->npage;
	up_write(&mm->mmap_sem);
	mmput(mm);		/* unref mm */
	kfree(vwork);
}

static void vfio_lock_acct(int npage)
{
	struct vwork *vwork;
	struct mm_struct *mm;

	if (!current->mm) {
		/* process exited */
		return;
	}
	if (down_write_trylock(&current->mm->mmap_sem)) {
		current->mm->locked_vm += npage;
		up_write(&current->mm->mmap_sem);
		return;
	}
	/*
	 * Couldn't get mmap_sem lock, so must setup to decrement
	 * mm->locked_vm later. If locked_vm were atomic, we wouldn't
	 * need this silliness
	 */
	vwork = kmalloc(sizeof(struct vwork), GFP_KERNEL);
	if (!vwork)
		return;
	mm = get_task_mm(current);	/* take ref mm */
	if (!mm) {
		kfree(vwork);
		return;
	}
	INIT_WORK(&vwork->work, vfio_lock_acct_bg);
	vwork->mm = mm;
	vwork->npage = npage;
	schedule_work(&vwork->work);
}

/* Unmap DMA region */
/* dgate must be held */
static void vfio_dma_unmap(struct vfio_listener *listener,
			struct dma_map_page *mlp)
{
	int i;
	struct vfio_dev *vdev = listener->vdev;
	int npage;

	list_del(&mlp->list);
	for (i = 0; i < mlp->npage; i++)
		(void) uiommu_unmap(vdev->udomain,
				mlp->daddr + i * PAGE_SIZE, 0);
	for (i = 0; i < mlp->npage; i++) {
		if (mlp->rdwr)
			SetPageDirty(mlp->pages[i]);
		put_page(mlp->pages[i]);
	}
	vdev->mapcount--;
	npage = mlp->npage;
	vdev->locked_pages -= mlp->npage;
	vfree(mlp->pages);
	kfree(mlp);
	vfio_lock_acct(-npage);
}

/* Unmap ALL DMA regions */
void vfio_dma_unmapall(struct vfio_listener *listener)
{
	struct list_head *pos, *pos2;
	struct dma_map_page *mlp;

	mutex_lock(&listener->vdev->dgate);
	list_for_each_safe(pos, pos2, &listener->dm_list) {
		mlp = list_entry(pos, struct dma_map_page, list);
		vfio_dma_unmap(listener, mlp);
	}
	mutex_unlock(&listener->vdev->dgate);
}

int vfio_dma_unmap_dm(struct vfio_listener *listener, struct vfio_dma_map *dmp)
{
	int npage;
	struct dma_map_page *mlp;
	struct list_head *pos, *pos2;
	int ret;

	npage = dmp->size >> PAGE_SHIFT;

	ret = -ENXIO;
	mutex_lock(&listener->vdev->dgate);
	list_for_each_safe(pos, pos2, &listener->dm_list) {
		mlp = list_entry(pos, struct dma_map_page, list);
		if (dmp->vaddr != mlp->vaddr || mlp->npage != npage)
			continue;
		ret = 0;
		vfio_dma_unmap(listener, mlp);
		break;
	}
	mutex_unlock(&listener->vdev->dgate);
	return ret;
}

#ifdef CONFIG_MMU_NOTIFIER
/* Handle MMU notifications - user process freed or realloced memory
 * which may be in use in a DMA region. Clean up region if so.
 */
static void vfio_dma_handle_mmu_notify(struct mmu_notifier *mn,
		unsigned long start, unsigned long end)
{
	struct vfio_listener *listener;
	unsigned long myend;
	struct list_head *pos, *pos2;
	struct dma_map_page *mlp;

	listener = container_of(mn, struct vfio_listener, mmu_notifier);
	mutex_lock(&listener->vdev->dgate);
	list_for_each_safe(pos, pos2, &listener->dm_list) {
		mlp = list_entry(pos, struct dma_map_page, list);
		if (mlp->vaddr >= end)
			continue;
		/*
		 * Ranges overlap if they're not disjoint; and they're
		 * disjoint if the end of one is before the start of
		 * the other one.
		 */
		myend = mlp->vaddr + (mlp->npage << PAGE_SHIFT) - 1;
		if (!(myend <= start || end <= mlp->vaddr)) {
			printk(KERN_WARNING
				"%s: demap start %lx end %lx va %lx pa %lx\n",
				__func__, start, end,
				mlp->vaddr, (long)mlp->daddr);
			vfio_dma_unmap(listener, mlp);
		}
	}
	mutex_unlock(&listener->vdev->dgate);
}

static void vfio_dma_inval_page(struct mmu_notifier *mn,
		struct mm_struct *mm, unsigned long addr)
{
	vfio_dma_handle_mmu_notify(mn, addr, addr + PAGE_SIZE);
}

static void vfio_dma_inval_range_start(struct mmu_notifier *mn,
		struct mm_struct *mm, unsigned long start, unsigned long end)
{
	vfio_dma_handle_mmu_notify(mn, start, end);
}

static const struct mmu_notifier_ops vfio_dma_mmu_notifier_ops = {
	.invalidate_page = vfio_dma_inval_page,
	.invalidate_range_start = vfio_dma_inval_range_start,
};
#endif	/* CONFIG_MMU_NOTIFIER */

/*
 * Map usr buffer at specific IO virtual address
 */
static struct dma_map_page *vfio_dma_map_iova(
		struct vfio_listener *listener,
		unsigned long start_iova,
		struct page **pages,
		int npage,
		int rdwr)
{
	struct vfio_dev *vdev = listener->vdev;
	int ret;
	int i;
	phys_addr_t hpa;
	struct dma_map_page *mlp;
	unsigned long iova = start_iova;

	if (!vdev->udomain)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < npage; i++) {
		if (uiommu_iova_to_phys(vdev->udomain, iova + i * PAGE_SIZE))
			return ERR_PTR(-EBUSY);
	}

	mlp = kzalloc(sizeof *mlp, GFP_KERNEL);
	if (!mlp)
		return ERR_PTR(-ENOMEM);
	rdwr = rdwr ? IOMMU_READ|IOMMU_WRITE : IOMMU_READ;
	if (vdev->cachec)
		rdwr |= IOMMU_CACHE;
	for (i = 0; i < npage; i++) {
		hpa = page_to_phys(pages[i]);
		ret = uiommu_map(vdev->udomain, iova, hpa, 0, rdwr);
		if (ret) {
			while (--i > 0) {
				iova -= PAGE_SIZE;
				(void) uiommu_unmap(vdev->udomain,
						iova, 0);
			}
			kfree(mlp);
			return ERR_PTR(ret);
		}
		iova += PAGE_SIZE;
	}
	vdev->mapcount++;

	mlp->pages = pages;
	mlp->daddr = start_iova;
	mlp->npage = npage;
	return mlp;
}

int vfio_dma_map_common(struct vfio_listener *listener,
		unsigned int cmd, struct vfio_dma_map *dmp)
{
	int locked, lock_limit;
	struct page **pages;
	int npage;
	struct dma_map_page *mlp;
	int rdwr = (dmp->flags & VFIO_FLAG_WRITE) ? 1 : 0;
	int ret = 0;

	if (dmp->vaddr & (PAGE_SIZE-1))
		return -EINVAL;
	if (dmp->dmaaddr & (PAGE_SIZE-1))
		return -EINVAL;
	if (dmp->size & (PAGE_SIZE-1))
		return -EINVAL;
	if (dmp->size > VFIO_MAX_MAP_SIZE)
		return -EINVAL;
	npage = dmp->size >> PAGE_SHIFT;

	mutex_lock(&listener->vdev->dgate);

	/* account for locked pages */
	locked = npage + current->mm->locked_vm;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		printk(KERN_WARNING "%s: RLIMIT_MEMLOCK exceeded\n",
			__func__);
		ret = -ENOMEM;
		goto out_lock;
	}
	/* only 1 address space per fd */
	if (current->mm != listener->mm) {
		if (listener->mm) {
			ret = -EINVAL;
			goto out_lock;
		}
		listener->mm = current->mm;
#ifdef CONFIG_MMU_NOTIFIER
		listener->mmu_notifier.ops = &vfio_dma_mmu_notifier_ops;
		ret = mmu_notifier_register(&listener->mmu_notifier,
						listener->mm);
		if (ret)
			printk(KERN_ERR "%s: mmu_notifier_register failed %d\n",
				__func__, ret);
		ret = 0;
#endif
	}

	pages = vmalloc(npage * sizeof(struct page *));
	if (!pages) {
		ret = -ENOMEM;
		goto out_lock;
	}
	ret = get_user_pages_fast(dmp->vaddr, npage, rdwr, pages);
	if (ret != npage) {
		printk(KERN_ERR "%s: get_user_pages_fast returns %d, not %d\n",
			__func__, ret, npage);
		kfree(pages);
		ret = -EFAULT;
		goto out_lock;
	}
	ret = 0;

	mlp = vfio_dma_map_iova(listener, dmp->dmaaddr,
				pages, npage, rdwr);
	if (IS_ERR(mlp)) {
		ret = PTR_ERR(mlp);
		vfree(pages);
		goto out_lock;
	}
	mlp->vaddr = dmp->vaddr;
	mlp->rdwr = rdwr;
	dmp->dmaaddr = mlp->daddr;
	list_add(&mlp->list, &listener->dm_list);

	vfio_lock_acct(npage);
	listener->vdev->locked_pages += npage;
out_lock:
	mutex_unlock(&listener->vdev->dgate);
	return ret;
}

int vfio_domain_unset(struct vfio_dev *vdev)
{
	struct pci_dev *pdev = vdev->pdev;

	if (!vdev->udomain)
		return 0;
	if (vdev->mapcount)
		return -EBUSY;
	uiommu_detach_device(vdev->udomain, &pdev->dev);
	uiommu_put(vdev->udomain);
	vdev->udomain = NULL;
	return 0;
}

int vfio_domain_set(struct vfio_dev *vdev, int fd, int unsafe_ok)
{
	struct uiommu_domain *udomain;
	struct pci_dev *pdev = vdev->pdev;
	int ret;
	int safe;

	if (vdev->udomain)
		return -EBUSY;
	udomain = uiommu_fdget(fd);
	if (IS_ERR(udomain))
		return PTR_ERR(udomain);

	safe = 0;
#ifdef IOMMU_CAP_INTR_REMAP	/* >= 2.6.36 */
	/* iommu domain must also isolate dev interrupts */
	if (uiommu_domain_has_cap(udomain, IOMMU_CAP_INTR_REMAP))
		safe = 1;
#endif
	if (!safe && !unsafe_ok) {
		printk(KERN_WARNING "%s: no interrupt remapping!\n", __func__);
		return -EINVAL;
	}

	vfio_domain_unset(vdev);
	ret = uiommu_attach_device(udomain, &pdev->dev);
	if (ret) {
		printk(KERN_ERR "%s: attach_device failed %d\n",
				__func__, ret);
		uiommu_put(udomain);
		return ret;
	}
	vdev->cachec = iommu_domain_has_cap(udomain->domain,
				IOMMU_CAP_CACHE_COHERENCY);
	vdev->udomain = udomain;
	return 0;
}
