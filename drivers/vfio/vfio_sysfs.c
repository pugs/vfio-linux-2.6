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
 * This code handles vfio related files in sysfs
 * (not much useful yet)
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/mmu_notifier.h>

#include <linux/vfio.h>

struct vfio_class *vfio_class;

int vfio_class_init(void)
{
	int ret = 0;

	if (vfio_class) {
		kref_get(&vfio_class->kref);
		goto exit;
	}

	vfio_class = kzalloc(sizeof(*vfio_class), GFP_KERNEL);
	if (!vfio_class) {
		ret = -ENOMEM;
		goto err_kzalloc;
	}

	kref_init(&vfio_class->kref);
	vfio_class->class = class_create(THIS_MODULE, "vfio");
	if (IS_ERR(vfio_class->class)) {
		ret = IS_ERR(vfio_class->class);
		printk(KERN_ERR "class_create failed for vfio\n");
		goto err_class_create;
	}
	return 0;

err_class_create:
	kfree(vfio_class);
	vfio_class = NULL;
err_kzalloc:
exit:
	return ret;
}

static void vfio_class_release(struct kref *kref)
{
	/* Ok, we cheat as we know we only have one vfio_class */
	class_destroy(vfio_class->class);
	kfree(vfio_class);
	vfio_class = NULL;
}

void vfio_class_destroy(void)
{
	if (vfio_class)
		kref_put(&vfio_class->kref, vfio_class_release);
}

static ssize_t show_locked_pages(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct vfio_dev *vdev = dev_get_drvdata(dev);

	if (!vdev)
		return -ENODEV;
	return sprintf(buf, "%u\n", vdev->locked_pages);
}

static DEVICE_ATTR(locked_pages, S_IRUGO, show_locked_pages, NULL);

static struct attribute *vfio_attrs[] = {
	&dev_attr_locked_pages.attr,
	NULL,
};

static struct attribute_group vfio_attr_grp = {
	.attrs = vfio_attrs,
};

int vfio_dev_add_attributes(struct vfio_dev *vdev)
{
	return sysfs_create_group(&vdev->dev->kobj, &vfio_attr_grp);
}
