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
 * VFIO main module: driver to allow non-privileged user programs
 * to imlpement direct mapped device drivers for PCI* devices
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/string.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/eventfd.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/mmu_notifier.h>
#include <linux/uaccess.h>
#include <linux/suspend.h>
#include <linux/compat.h>
#include <linux/delay.h>

#include <linux/vfio.h>


#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"Tom Lyon <pugs@cisco.com>"
#define DRIVER_DESC	"VFIO - User Level PCI meta-driver"

/*
 * Only a very few platforms today (Intel X7500) fully support
 * both DMA remapping and interrupt remapping in the IOMMU.
 * Everyone has DMA remapping but interrupt remapping is missing
 * in some Intel hardware and software, and its missing in the AMD
 * IOMMU software. Interrupt remapping is needed to really protect the
 * system from user level driver mischief.  Until it is in more platforms
 * we allow the admin to load the module with allow_unsafe_intrs=1
 * which will make this driver useful (but not safe)
 * on those platforms.
 */
static int allow_unsafe_intrs;
module_param(allow_unsafe_intrs, int, 0);
MODULE_PARM_DESC(allow_unsafe_intrs, "Allow use of IOMMUs which do not support interrupt remapping");

static int vfio_major = -1;
static DEFINE_IDR(vfio_idr);
static int vfio_max_minor;
/* Protect idr accesses */
static DEFINE_MUTEX(vfio_minor_lock);

/*
 * Does [a1,b1) overlap [a2,b2) ?
 */
static inline int overlap(int a1, int b1, int a2, int b2)
{
	/*
	 * Ranges overlap if they're not disjoint; and they're
	 * disjoint if the end of one is before the start of
	 rq
* the other one.
	 */
	return !(b2 <= a1 || b1 <= a2);
}

static int vfio_open(struct inode *inode, struct file *filep)
{
	struct vfio_dev *vdev;
	struct vfio_listener *listener;
	int ret = 0;

	mutex_lock(&vfio_minor_lock);
	vdev = idr_find(&vfio_idr, iminor(inode));
	mutex_unlock(&vfio_minor_lock);
	if (!vdev) {
		ret = -ENODEV;
		goto out;
	}

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener) {
		ret = -ENOMEM;
		goto out;
	}

	mutex_lock(&vdev->lgate);
	listener->vdev = vdev;
	INIT_LIST_HEAD(&listener->dm_list);
	if (vdev->listeners == 0) {
		u16 cmd;
		(void) pci_reset_function(vdev->pdev);
		msleep(100);	/* 100ms for reset recovery */
		pci_read_config_word(vdev->pdev, PCI_COMMAND, &cmd);
		if (vdev->pci_2_3 && (cmd & PCI_COMMAND_INTX_DISABLE)) {
			cmd &= ~PCI_COMMAND_INTX_DISABLE;
			pci_write_config_word(vdev->pdev, PCI_COMMAND, cmd);
		}
		ret = pci_enable_device(vdev->pdev);
	}
	if (!ret) {
		filep->private_data = listener;
		vdev->listeners++;
	}
	mutex_unlock(&vdev->lgate);
	if (ret)
		kfree(listener);
out:
	return ret;
}

/*
 * Disable PCI device
 * Can't call pci_reset_function here because it needs the
 * device lock which may be held during _remove events
 */
static void vfio_disable_pci(struct vfio_dev *vdev)
{
	int bar;
	struct pci_dev *pdev = vdev->pdev;

	for (bar = PCI_STD_RESOURCES; bar <= PCI_STD_RESOURCE_END; bar++) {
		if (!vdev->barmap[bar])
			continue;
		pci_iounmap(pdev, vdev->barmap[bar]);
		pci_release_selected_regions(pdev, 1 << bar);
		vdev->barmap[bar] = NULL;
	}
	pci_disable_device(pdev);
}

static int vfio_release(struct inode *inode, struct file *filep)
{
	int ret = 0;
	struct vfio_listener *listener = filep->private_data;
	struct vfio_dev *vdev = listener->vdev;

	vfio_dma_unmapall(listener);
	if (listener->mm) {
#ifdef CONFIG_MMU_NOTIFIER
		mmu_notifier_unregister(&listener->mmu_notifier, listener->mm);
#endif
		listener->mm = NULL;
	}

	mutex_lock(&vdev->lgate);
	if (--vdev->listeners <= 0) {
		/* we don't need to hold igate here since there are
		 * no more listeners doing ioctls
		 */
		if (vdev->ev_msix)
			vfio_drop_msix(vdev);
		if (vdev->ev_msi)
			vfio_drop_msi(vdev);
		if (vdev->ev_irq) {
			free_irq(vdev->pdev->irq, vdev);
			eventfd_ctx_put(vdev->ev_irq);
			vdev->ev_irq = NULL;
			vdev->irq_disabled = false;
			vdev->virq_disabled = false;
		}
		kfree(vdev->vconfig);
		vdev->vconfig = NULL;
		kfree(vdev->pci_config_map);
		vdev->pci_config_map = NULL;
		vfio_disable_pci(vdev);
		vfio_domain_unset(vdev);
		wake_up(&vdev->dev_idle_q);
	}
	mutex_unlock(&vdev->lgate);

	kfree(listener);
	return ret;
}

static ssize_t vfio_read(struct file *filep, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vfio_listener *listener = filep->private_data;
	struct vfio_dev *vdev = listener->vdev;
	struct pci_dev *pdev = vdev->pdev;
	u8 pci_space;

	pci_space = vfio_offset_to_pci_space(*ppos);

	/* config reads are OK before iommu domain set */
	if (pci_space == VFIO_PCI_CONFIG_RESOURCE)
		return vfio_config_readwrite(0, vdev, buf, count, ppos);

	/* no other reads until IOMMU domain set */
	if (!vdev->udomain)
		return -EINVAL;
	if (pci_space > PCI_ROM_RESOURCE)
		return -EINVAL;
	if (pci_resource_flags(pdev, pci_space) & IORESOURCE_IO)
		return vfio_io_readwrite(0, vdev, buf, count, ppos);
	else if (pci_resource_flags(pdev, pci_space) & IORESOURCE_MEM)
		return vfio_mem_readwrite(0, vdev, buf, count, ppos);
	else if (pci_space == PCI_ROM_RESOURCE)
		return vfio_mem_readwrite(0, vdev, buf, count, ppos);
	return -EINVAL;
}

static int vfio_msix_check(struct vfio_dev *vdev, u64 start, u32 len)
{
	struct pci_dev *pdev = vdev->pdev;
	u16 pos;
	u32 table_offset;
	u16 table_size;
	u8 bir;
	u32 lo, hi, startp, endp;

	pos = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (!pos)
		return 0;

	pci_read_config_word(pdev, pos + PCI_MSIX_FLAGS, &table_size);
	table_size = (table_size & PCI_MSIX_FLAGS_QSIZE) + 1;
	pci_read_config_dword(pdev, pos + 4, &table_offset);
	bir = table_offset & PCI_MSIX_FLAGS_BIRMASK;
	lo = table_offset >> PAGE_SHIFT;
	hi = (table_offset + PCI_MSIX_ENTRY_SIZE * table_size + PAGE_SIZE - 1)
		>> PAGE_SHIFT;
	startp = start >> PAGE_SHIFT;
	endp = (start + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (bir == vfio_offset_to_pci_space(start) &&
	    overlap(lo, hi, startp, endp)) {
		printk(KERN_WARNING "%s: cannot write msi-x vectors\n",
			__func__);
		return -EINVAL;
	}
	return 0;
}

static ssize_t vfio_write(struct file *filep, const char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vfio_listener *listener = filep->private_data;
	struct vfio_dev *vdev = listener->vdev;
	struct pci_dev *pdev = vdev->pdev;
	u8 pci_space;
	int ret;

	/* no writes until IOMMU domain set */
	if (!vdev->udomain)
		return -EINVAL;
	pci_space = vfio_offset_to_pci_space(*ppos);
	if (pci_space == VFIO_PCI_CONFIG_RESOURCE)
		return vfio_config_readwrite(1, vdev,
					(char __user *)buf, count, ppos);
	if (pci_space > PCI_ROM_RESOURCE)
		return -EINVAL;
	if (pci_resource_flags(pdev, pci_space) & IORESOURCE_IO)
		return vfio_io_readwrite(1, vdev,
					(char __user *)buf, count, ppos);
	else if (pci_resource_flags(pdev, pci_space) & IORESOURCE_MEM) {
		if (allow_unsafe_intrs) {
			/* don't allow writes to msi-x vectors */
			ret = vfio_msix_check(vdev, *ppos, count);
			if (ret)
				return ret;
		}
		return vfio_mem_readwrite(1, vdev,
				(char __user *)buf, count, ppos);
	}
	return -EINVAL;
}

static int vfio_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vfio_listener *listener = filep->private_data;
	struct vfio_dev *vdev = listener->vdev;
	struct pci_dev *pdev = vdev->pdev;
	unsigned long requested, actual;
	int pci_space;
	u64 start;
	u32 len;
	unsigned long phys;
	int ret;

	/* no reads or writes until IOMMU domain set */
	if (!vdev->udomain)
		return -EINVAL;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;


	pci_space = vfio_offset_to_pci_space((u64)vma->vm_pgoff << PAGE_SHIFT);
	/*
	 * Can't mmap ROM - see vfio_mem_readwrite
	 */
	if (pci_space > PCI_STD_RESOURCE_END)
		return -EINVAL;
	if ((pci_resource_flags(pdev, pci_space) & IORESOURCE_MEM) == 0)
		return -EINVAL;
	actual = pci_resource_len(pdev, pci_space) >> PAGE_SHIFT;

	requested = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	if (requested > actual || actual == 0)
		return -EINVAL;

	/*
	 * Even though we don't make use of the barmap for the mmap,
	 * we need to request the region and the barmap tracks that.
	 */
	if (!vdev->barmap[pci_space]) {
		ret = pci_request_selected_regions(pdev, (1 << pci_space),
						   vdev->name);
		if (ret)
			return ret;
		vdev->barmap[pci_space] = pci_iomap(pdev, pci_space, 0);
	}

	start = vma->vm_pgoff << PAGE_SHIFT;
	len = vma->vm_end - vma->vm_start;
	if (allow_unsafe_intrs && (vma->vm_flags & VM_WRITE)) {
		/*
		 * Deter users from screwing up MSI-X intrs
		 */
		ret = vfio_msix_check(vdev, start, len);
		if (ret)
			return ret;
	}

	vma->vm_private_data = vdev;
	vma->vm_flags |= VM_IO | VM_RESERVED;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	phys = pci_resource_start(pdev, pci_space) >> PAGE_SHIFT;

	return remap_pfn_range(vma, vma->vm_start, phys,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

static long vfio_unl_ioctl(struct file *filep,
			unsigned int cmd,
			unsigned long arg)
{
	struct vfio_listener *listener = filep->private_data;
	struct vfio_dev *vdev = listener->vdev;
	void __user *uarg = (void __user *)arg;
	int __user *intargp = (void __user *)arg;
	struct pci_dev *pdev = vdev->pdev;
	struct vfio_dma_map dm;
	int ret = 0;
	int fd, nfd;
	int bar;

	if (!vdev)
		return -EINVAL;

	switch (cmd) {

	case VFIO_DMA_MAP_IOVA:
		if (copy_from_user(&dm, uarg, sizeof dm))
			return -EFAULT;
		ret = vfio_dma_map_common(listener, cmd, &dm);
		if (!ret && copy_to_user(uarg, &dm, sizeof dm))
			ret = -EFAULT;
		break;

	case VFIO_DMA_UNMAP:
		if (copy_from_user(&dm, uarg, sizeof dm))
			return -EFAULT;
		ret = vfio_dma_unmap_dm(listener, &dm);
		break;

	case VFIO_EVENTFD_IRQ:
		if (get_user(fd, intargp))
			return -EFAULT;
		if (!pdev->irq)
			return -EINVAL;
		mutex_lock(&vdev->igate);
		if (vdev->ev_irq) {
			eventfd_ctx_put(vdev->ev_irq);
			free_irq(pdev->irq, vdev);
			vdev->irq_disabled = false;
			vdev->ev_irq = NULL;
		}
		if (vdev->ev_msi) {	/* irq and msi both use pdev->irq */
			ret = -EINVAL;
		} else {
			if (fd >= 0) {
				vdev->ev_irq = eventfd_ctx_fdget(fd);
				if (vdev->ev_irq) {
					ret = request_irq(pdev->irq,
						vfio_interrupt,
						vdev->pci_2_3 ? IRQF_SHARED : 0,
						vdev->name, vdev);
					if (vdev->virq_disabled)
						vfio_disable_intx(vdev);
				}
				else
					ret = -EINVAL;
			}
		}
		mutex_unlock(&vdev->igate);
		break;

	case VFIO_EVENTFDS_MSI:
		if (get_user(nfd, intargp))
			return -EFAULT;
		intargp++;
		mutex_lock(&vdev->igate);
		if (vdev->ev_irq) {	/* irq and msi both use pdev->irq */
			ret = -EINVAL;
		} else {
			if (nfd > 0 && !vdev->ev_msi)
				ret = vfio_setup_msi(vdev, nfd, intargp);
			else if (nfd == 0 && vdev->ev_msi)
				vfio_drop_msi(vdev);
			else
				ret = -EINVAL;
		}
		mutex_unlock(&vdev->igate);
		break;

	case VFIO_EVENTFDS_MSIX:
		if (get_user(nfd, intargp))
			return -EFAULT;
		intargp++;
		mutex_lock(&vdev->igate);
		if (nfd > 0 && !vdev->ev_msix)
			ret = vfio_setup_msix(vdev, nfd, intargp);
		else if (nfd == 0 && vdev->ev_msix)
			vfio_drop_msix(vdev);
		else
			ret = -EINVAL;
		mutex_unlock(&vdev->igate);
		break;

	case VFIO_BAR_LEN:
		if (get_user(bar, intargp))
			return -EFAULT;
		if (bar < 0 || bar > PCI_ROM_RESOURCE)
			return -EINVAL;
		if (pci_resource_start(pdev, bar))
			bar = pci_resource_len(pdev, bar);
		else
			bar = 0;
		if (put_user(bar, intargp))
			return -EFAULT;
		break;

	case VFIO_DOMAIN_SET:
		if (get_user(fd, intargp))
			return -EFAULT;
		ret = vfio_domain_set(vdev, fd, allow_unsafe_intrs);
		break;

	case VFIO_DOMAIN_UNSET:
		ret = vfio_domain_unset(vdev);
		break;

	case VFIO_IRQ_EOI:
		ret = vfio_irq_eoi(vdev);
		break;

	case VFIO_IRQ_EOI_EVENTFD:
		if (copy_from_user(&fd, uarg, sizeof fd))
			return -EFAULT;
		ret = vfio_irq_eoi_eventfd(vdev, fd);
		break;

	default:
		return -EINVAL;
	}
	return ret;
}

#ifdef CONFIG_COMPAT
static long vfio_compat_ioctl(struct file *filep,
			unsigned int cmd,
			unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

static const struct file_operations vfio_fops = {
	.owner		= THIS_MODULE,
	.open		= vfio_open,
	.release	= vfio_release,
	.read		= vfio_read,
	.write		= vfio_write,
	.unlocked_ioctl	= vfio_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_compat_ioctl,
#endif
	.mmap		= vfio_mmap,
};

static int vfio_get_devnum(struct vfio_dev *vdev)
{
	int retval = -ENOMEM;
	int id;

	mutex_lock(&vfio_minor_lock);
	if (idr_pre_get(&vfio_idr, GFP_KERNEL) == 0)
		goto exit;

	retval = idr_get_new(&vfio_idr, vdev, &id);
	if (retval < 0) {
		if (retval == -EAGAIN)
			retval = -ENOMEM;
		goto exit;
	}
	if (id > MINORMASK) {
		idr_remove(&vfio_idr, id);
		retval = -ENOMEM;
	}
	if (id > vfio_max_minor)
		vfio_max_minor = id;
	if (vfio_major < 0) {
		retval = register_chrdev(0, "vfio", &vfio_fops);
		if (retval < 0)
			goto exit;
		vfio_major = retval;
	}

	retval = MKDEV(vfio_major, id);
exit:
	mutex_unlock(&vfio_minor_lock);
	return retval;
}

int vfio_validate(struct vfio_dev *vdev)
{
	int rc = 0;
	int id;

	mutex_lock(&vfio_minor_lock);
	for (id = 0; id <= vfio_max_minor; id++)
		if (vdev == idr_find(&vfio_idr, id))
			goto out;
	rc = 1;
out:
	mutex_unlock(&vfio_minor_lock);
	return rc;
}

static void vfio_free_minor(struct vfio_dev *vdev)
{
	mutex_lock(&vfio_minor_lock);
	idr_remove(&vfio_idr, MINOR(vdev->devnum));
	mutex_unlock(&vfio_minor_lock);
}

/*
 * Verify that the device supports Interrupt Disable bit in command register,
 * per PCI 2.3, by flipping this bit and reading it back: this bit was readonly
 * in PCI 2.2.  (from uio_pci_generic)
 */
static int verify_pci_2_3(struct pci_dev *pdev)
{
	u16 orig, new;
	u8 pin;

	pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &pin);
	if (pin == 0)		/* irqs not needed */
		return 0;

	pci_read_config_word(pdev, PCI_COMMAND, &orig);
	pci_write_config_word(pdev, PCI_COMMAND,
			      orig ^ PCI_COMMAND_INTX_DISABLE);
	pci_read_config_word(pdev, PCI_COMMAND, &new);
	/* There's no way to protect against
	 * hardware bugs or detect them reliably, but as long as we know
	 * what the value should be, let's go ahead and check it. */
	if ((new ^ orig) & ~PCI_COMMAND_INTX_DISABLE) {
		dev_err(&pdev->dev, "Command changed from 0x%x to 0x%x: "
			"driver or HW bug?\n", orig, new);
		return -EBUSY;
	}
	if (!((new ^ orig) & PCI_COMMAND_INTX_DISABLE)) {
		dev_warn(&pdev->dev, "Device does not support disabling "
			 "interrupts, exclusive interrupt required.\n");
		return -ENODEV;
	}
	/* Now restore the original value. */
	pci_write_config_word(pdev, PCI_COMMAND, orig);
	return 0;
}

static int vfio_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct vfio_dev *vdev;
	int err;
	u8 type;

	if (!iommu_found())
		return -EINVAL;

	pci_read_config_byte(pdev, PCI_HEADER_TYPE, &type);
	if ((type & 0x7F) != PCI_HEADER_TYPE_NORMAL)
		return -EINVAL;

	vdev = kzalloc(sizeof(struct vfio_dev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;
	vdev->pdev = pdev;

	vdev->pci_2_3 = (verify_pci_2_3(pdev) == 0);

	mutex_init(&vdev->lgate);
	mutex_init(&vdev->dgate);
	mutex_init(&vdev->igate);
	mutex_init(&vdev->ngate);
	INIT_LIST_HEAD(&vdev->nlc_list);
	init_waitqueue_head(&vdev->dev_idle_q);
	init_waitqueue_head(&vdev->nl_wait_q);

	err = vfio_get_devnum(vdev);
	if (err < 0)
		goto err_get_devnum;
	vdev->devnum = err;
	err = 0;

	sprintf(vdev->name, "vfio%d", MINOR(vdev->devnum));
	pci_set_drvdata(pdev, vdev);
	vdev->dev = device_create(vfio_class->class, &pdev->dev,
			  vdev->devnum, vdev, vdev->name);
	if (IS_ERR(vdev->dev)) {
		printk(KERN_ERR "VFIO: device register failed\n");
		err = PTR_ERR(vdev->dev);
		goto err_device_create;
	}

	err = vfio_dev_add_attributes(vdev);
	if (err)
		goto err_vfio_dev_add_attributes;

	return 0;

err_vfio_dev_add_attributes:
	device_destroy(vfio_class->class, vdev->devnum);
err_device_create:
	vfio_free_minor(vdev);
err_get_devnum:
	kfree(vdev);
	return err;
}

static void vfio_remove(struct pci_dev *pdev)
{
	struct vfio_dev *vdev = pci_get_drvdata(pdev);
	int ret;

	/* prevent further opens */
	vfio_free_minor(vdev);

	/* notify users */
	ret = vfio_nl_remove(vdev);

	/* wait for all closed */
	wait_event(vdev->dev_idle_q, vdev->listeners == 0);

	pci_disable_device(pdev);

	vfio_nl_freeclients(vdev);
	device_destroy(vfio_class->class, vdev->devnum);
	pci_set_drvdata(pdev, NULL);
	kfree(vdev);
}

static struct pci_error_handlers vfio_error_handlers = {
	.error_detected	= vfio_error_detected,
	.mmio_enabled	= vfio_mmio_enabled,
	.link_reset	= vfio_link_reset,
	.slot_reset	= vfio_slot_reset,
	.resume		= vfio_error_resume,
};

static struct pci_driver driver = {
	.name		= "vfio",
	.id_table	= NULL, /* only dynamic id's */
	.probe		 = vfio_probe,
	.remove		 = vfio_remove,
	.err_handler	 = &vfio_error_handlers,
};

static atomic_t vfio_pm_suspend_count;
static int vfio_pm_suspend_result;
static DECLARE_WAIT_QUEUE_HEAD(vfio_pm_wait_q);

/*
 * Notify user level drivers of hibernation/suspend request
 * Send all the notifies in parallel, collect all the replies
 * If one ULD can't suspend, none can
 */
static int vfio_pm_suspend(void)
{
	struct vfio_dev *vdev;
	int id, alive = 0;
	int ret;

	mutex_lock(&vfio_minor_lock);
	atomic_set(&vfio_pm_suspend_count, 0);
	vfio_pm_suspend_result = NOTIFY_DONE;
	for (id = 0; id <= vfio_max_minor; id++) {
		vdev = idr_find(&vfio_idr, id);
		if (!vdev)
			continue;
		if (vdev->listeners == 0)
			continue;
		alive++;
		ret = vfio_nl_upcall(vdev, VFIO_MSG_PM_SUSPEND, 0, 0);
		if (ret == 0)
			atomic_inc(&vfio_pm_suspend_count);
	}
	mutex_unlock(&vfio_minor_lock);
	if (alive > atomic_read(&vfio_pm_suspend_count))
		return NOTIFY_BAD;

	/* sleep for reply */
	if (wait_event_interruptible_timeout(vfio_pm_wait_q,
	    (atomic_read(&vfio_pm_suspend_count) == 0),
	    VFIO_SUSPEND_REPLY_TIMEOUT) <= 0) {
		printk(KERN_ERR "vfio upcall suspend reply timeout\n");
		return NOTIFY_BAD;
	}
	return vfio_pm_suspend_result;
}

static int vfio_pm_resume(void)
{
	struct vfio_dev *vdev;
	int id;

	mutex_lock(&vfio_minor_lock);
	for (id = 0; id <= vfio_max_minor; id++) {
		vdev = idr_find(&vfio_idr, id);
		if (!vdev)
			continue;
		if (vdev->listeners == 0)
			continue;
		(void) vfio_nl_upcall(vdev, VFIO_MSG_PM_RESUME, 0, 0);
	}
	mutex_unlock(&vfio_minor_lock);
	return NOTIFY_DONE;
}


void vfio_pm_process_reply(int reply)
{
	if (vfio_pm_suspend_result == NOTIFY_DONE) {
		if (reply != NOTIFY_DONE)
			vfio_pm_suspend_result = NOTIFY_BAD;
	}
	if (atomic_dec_and_test(&vfio_pm_suspend_count))
		wake_up(&vfio_pm_wait_q);
}

static int vfio_pm_notify(struct notifier_block *this, unsigned long event,
	void *notused)
{
	switch (event) {
	case PM_HIBERNATION_PREPARE:
	case PM_SUSPEND_PREPARE:
		return vfio_pm_suspend();
		break;
	case PM_POST_HIBERNATION:
	case PM_POST_SUSPEND:
		return vfio_pm_resume();
		break;
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block vfio_pm_nb = {
	.notifier_call = vfio_pm_notify,
};

static int __init init(void)
{
	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");
	vfio_init_pci_perm_bits();
	vfio_class_init();
	vfio_nl_init();
	register_pm_notifier(&vfio_pm_nb);
	vfio_eoi_module_init();
	return pci_register_driver(&driver);
}

static void __exit cleanup(void)
{
	if (vfio_major >= 0)
		unregister_chrdev(vfio_major, "vfio");
	pci_unregister_driver(&driver);
	vfio_eoi_module_exit();
	unregister_pm_notifier(&vfio_pm_nb);
	vfio_nl_exit();
	vfio_class_destroy();
}

module_init(init);
module_exit(cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
