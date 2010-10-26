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
*/

/*
 * uiommu driver - issue fd handles for IOMMU domains
 * so they may be passed to vfio (and others?)
 */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/iommu.h>
#include <linux/uiommu.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tom Lyon <pugs@cisco.com>");
MODULE_DESCRIPTION("User IOMMU driver");

static struct uiommu_domain *uiommu_domain_alloc(void)
{
	struct iommu_domain *domain;
	struct uiommu_domain *udomain;

	domain = iommu_domain_alloc();
	if (!domain)
		return NULL;
	udomain = kzalloc(sizeof *udomain, GFP_KERNEL);
	if (!udomain) {
		iommu_domain_free(domain);
		return NULL;
	}
	udomain->domain = domain;
	atomic_inc(&udomain->refcnt);
	return udomain;
}

static int uiommu_open(struct inode *inode, struct file *file)
{
	struct uiommu_domain *udomain;

	udomain = uiommu_domain_alloc();
	if (!udomain)
		return -ENOMEM;
	file->private_data = udomain;
	return 0;
}

static int uiommu_release(struct inode *inode, struct file *file)
{
	struct uiommu_domain *udomain;

	udomain = file->private_data;
	uiommu_put(udomain);
	return 0;
}

static const struct file_operations uiommu_fops = {
	.owner		= THIS_MODULE,
	.open		= uiommu_open,
	.release	= uiommu_release,
};

static struct miscdevice uiommu_dev = {
	.name	= "uiommu",
	.minor	= MISC_DYNAMIC_MINOR,
	.fops	= &uiommu_fops,
};

struct uiommu_domain *uiommu_fdget(int fd)
{
	struct file *file;
	struct uiommu_domain *udomain;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &uiommu_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	udomain = file->private_data;
	atomic_inc(&udomain->refcnt);
	return udomain;
}
EXPORT_SYMBOL_GPL(uiommu_fdget);

void uiommu_put(struct uiommu_domain *udomain)
{
	if (atomic_dec_and_test(&udomain->refcnt)) {
		iommu_domain_free(udomain->domain);
		kfree(udomain);
	}
}
EXPORT_SYMBOL_GPL(uiommu_put);

static int __init uiommu_init(void)
{
	return misc_register(&uiommu_dev);
}

static void __exit uiommu_exit(void)
{
	misc_deregister(&uiommu_dev);
}

module_init(uiommu_init);
module_exit(uiommu_exit);
