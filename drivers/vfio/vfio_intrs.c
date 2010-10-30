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
 * This code handles catching interrupts and translating
 * them to events on eventfds
 */

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/eventfd.h>
#include <linux/pci.h>
#include <linux/mmu_notifier.h>

#include <linux/vfio.h>


/*
 * vfio_interrupt - IRQ hardware interrupt handler
 */
irqreturn_t vfio_interrupt(int irq, void *dev_id)
{
	struct vfio_dev *vdev = dev_id;
	struct pci_dev *pdev = vdev->pdev;
	irqreturn_t ret = IRQ_NONE;
	u32 cmd_status_dword;
	u16 origcmd, newcmd, status;

	spin_lock_irq(&vdev->irqlock);

	if (vdev->pci_2_3) {
		pci_block_user_cfg_access(pdev);

		/* Read both command and status registers in a single 32-bit
		 * operation. Note: we could cache the value for command and
		 * move the status read out of the lock if there was a way to
		 * get notified of user changes to command register through
		 * sysfs. Should be good for shared irqs. */
		pci_read_config_dword(pdev, PCI_COMMAND, &cmd_status_dword);
		origcmd = cmd_status_dword;
		status = cmd_status_dword >> 16;

		/* Check interrupt status register to see whether our device
	 	* triggered the interrupt. */
		if (!(status & PCI_STATUS_INTERRUPT))
			goto done;

		/* We triggered the interrupt, disable it. */
		newcmd = origcmd | PCI_COMMAND_INTX_DISABLE;
		if (newcmd != origcmd)
			pci_write_config_word(pdev, PCI_COMMAND, newcmd);

		ret = IRQ_HANDLED;
done:
		pci_unblock_user_cfg_access(pdev);
	} else {
		disable_irq_nosync(pdev->irq);
		ret = IRQ_HANDLED;
	}

	vdev->irq_disabled = (ret == IRQ_HANDLED);

	spin_unlock_irq(&vdev->irqlock);

	if (ret != IRQ_HANDLED)
		return ret;

	if (vdev->ev_irq)
		eventfd_signal(vdev->ev_irq, 1);
	return ret;
}

int vfio_irq_eoi(struct vfio_dev *vdev)
{
	struct pci_dev *pdev = vdev->pdev;

	spin_lock_irq(&vdev->irqlock);

	if (vdev->irq_disabled) {
		if (vdev->pci_2_3) {
			u16 cmd;
			pci_block_user_cfg_access(pdev);

			pci_read_config_word(pdev, PCI_COMMAND, &cmd);
			cmd &= ~PCI_COMMAND_INTX_DISABLE;
			pci_write_config_word(pdev, PCI_COMMAND, cmd);

			pci_unblock_user_cfg_access(pdev);
		} else
			enable_irq(pdev->irq);

		vdev->irq_disabled = false;
	}

	spin_unlock_irq(&vdev->irqlock);
	return 0;
}

/*
 * MSI and MSI-X Interrupt handler.
 * Just signal an event
 */
static irqreturn_t msihandler(int irq, void *arg)
{
	struct eventfd_ctx *ctx = arg;

	eventfd_signal(ctx, 1);
	return IRQ_HANDLED;
}

void vfio_drop_msi(struct vfio_dev *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int i;

	if (vdev->ev_msi) {
		for (i = 0; i < vdev->msi_nvec; i++) {
			free_irq(pdev->irq + i, vdev->ev_msi[i]);
			if (vdev->ev_msi[i])
				eventfd_ctx_put(vdev->ev_msi[i]);
		}
	}
	kfree(vdev->ev_msi);
	vdev->ev_msi = NULL;
	vdev->msi_nvec = 0;
	pci_disable_msi(pdev);
}

int vfio_setup_msi(struct vfio_dev *vdev, int nvec, int __user *intargp)
{
	struct pci_dev *pdev = vdev->pdev;
	struct eventfd_ctx *ctx;
	int i;
	int ret = 0;
	int fd;

	if (nvec < 1 || nvec > 32)
		return -EINVAL;
	vdev->ev_msi = kzalloc(nvec * sizeof(struct eventfd_ctx *),
				GFP_KERNEL);
	if (!vdev->ev_msi)
		return -ENOMEM;

	for (i = 0; i < nvec; i++) {
		if (get_user(fd, intargp)) {
			ret = -EFAULT;
			goto out;
		}
		intargp++;
		ctx = eventfd_ctx_fdget(fd);
		if (IS_ERR(ctx)) {
			ret = PTR_ERR(ctx);
			goto out;
		}
		vdev->ev_msi[i] = ctx;
	}
	ret = pci_enable_msi_block(pdev, nvec);
	if (ret) {
		if (ret > 0)
			ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < nvec; i++) {
		ret = request_irq(pdev->irq + i, msihandler, 0,
			vdev->name, vdev->ev_msi[i]);
		if (ret)
			goto out;
		vdev->msi_nvec = i+1;
	}

	/*
	 * compute the virtual hardware field for max msi vectors -
	 * it is the log base 2 of the number of vectors
	 */
	vdev->msi_qmax = fls(vdev->msi_nvec * 2 - 1) - 1;
out:
	if (ret)
		vfio_drop_msi(vdev);
	return ret;
}

void vfio_drop_msix(struct vfio_dev *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int i;

	if (vdev->ev_msix && vdev->msix) {
		for (i = 0; i < vdev->msix_nvec; i++) {
			free_irq(vdev->msix[i].vector, vdev->ev_msix[i]);
			if (vdev->ev_msix[i])
				eventfd_ctx_put(vdev->ev_msix[i]);
		}
	}
	kfree(vdev->ev_msix);
	vdev->ev_msix = NULL;
	kfree(vdev->msix);
	vdev->msix = NULL;
	vdev->msix_nvec = 0;
	pci_disable_msix(pdev);
}

int vfio_setup_msix(struct vfio_dev *vdev, int nvec, int __user *intargp)
{
	struct pci_dev *pdev = vdev->pdev;
	struct eventfd_ctx *ctx;
	int ret = 0;
	int i;
	int fd;
	int pos;
	u16 flags = 0;

	pos = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (!pos)
		return -EINVAL;
	pci_read_config_word(pdev, pos + PCI_MSIX_FLAGS, &flags);
	if (nvec < 1 || nvec > (flags & PCI_MSIX_FLAGS_QSIZE) + 1)
		return -EINVAL;

	vdev->msix = kzalloc(nvec * sizeof(struct msix_entry),
				GFP_KERNEL);
	if (!vdev->msix)
		return -ENOMEM;
	vdev->ev_msix = kzalloc(nvec * sizeof(struct eventfd_ctx *),
				GFP_KERNEL);
	if (!vdev->ev_msix) {
		kfree(vdev->msix);
		return -ENOMEM;
	}
	for (i = 0; i < nvec; i++) {
		if (get_user(fd, intargp)) {
			ret = -EFAULT;
			break;
		}
		intargp++;
		ctx = eventfd_ctx_fdget(fd);
		if (IS_ERR(ctx)) {
			ret = PTR_ERR(ctx);
			break;
		}
		vdev->msix[i].entry = i;
		vdev->ev_msix[i] = ctx;
	}
	if (!ret)
		ret = pci_enable_msix(pdev, vdev->msix, nvec);
	vdev->msix_nvec = 0;
	for (i = 0; i < nvec && !ret; i++) {
		ret = request_irq(vdev->msix[i].vector, msihandler, 0,
			vdev->name, vdev->ev_msix[i]);
		if (ret)
			break;
		vdev->msix_nvec = i+1;
	}
	if (ret)
		vfio_drop_msix(vdev);
	return ret;
}
