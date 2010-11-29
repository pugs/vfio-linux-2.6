/*
 * Netlink inteface for VFIO
 * Author: Tom Lyon (pugs@cisco.com)
 *
 * Copyright 2010, Cisco Systems, Inc.
 * Copyright 2007, 2008 Siemens AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Derived from net/ieee802154/netlink.c Written by:
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Maxim Osipov <maxim.osipov@siemens.com>
 */

/*
 * This code handles the signaling of various system events
 * to the user level driver, using the generic netlink facilities.
 * In many cases, we wait for replies from the user driver as well.
 */

#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <net/genetlink.h>
#include <linux/mmu_notifier.h>
#include <linux/vfio.h>

static u32 vfio_seq_num;
static DEFINE_SPINLOCK(vfio_seq_lock);

static struct genl_family vfio_nl_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= 0,
	.name		= VFIO_GENL_NAME,
	.version	= 1,
	.maxattr	= VFIO_NL_ATTR_MAX,
};

/* Requests to userspace */
static struct sk_buff *vfio_nl_create(u8 req)
{
	void *hdr;
	struct sk_buff *msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	unsigned long f;

	if (!msg)
		return NULL;

	spin_lock_irqsave(&vfio_seq_lock, f);
	hdr = genlmsg_put(msg, 0, ++vfio_seq_num,
			&vfio_nl_family, 0, req);
	spin_unlock_irqrestore(&vfio_seq_lock, f);
	if (!hdr) {
		nlmsg_free(msg);
		return NULL;
	}

	return msg;
}

/*
 * We would have liked to use NL multicast, but
 * (a) multicast sockets are only for root
 * (b) there's no multicast user level api in libnl
 * (c) we need to know what net namespaces are involved
 * Sigh.
 */
static int vfio_nl_mcast(struct vfio_dev *vdev, struct sk_buff *msg, u8 type)
{
	struct list_head *pos;
	struct vfio_nl_client *nlc;
	struct sk_buff *skb;
	/* XXX: nlh is right at the start of msg */
	void *hdr = genlmsg_data(NLMSG_DATA(msg->data));
	int good = 0;
	int rc;

	if (genlmsg_end(msg, hdr) < 0) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	mutex_lock(&vdev->ngate);
	list_for_each(pos, &vdev->nlc_list) {
		nlc = list_entry(pos, struct vfio_nl_client, list);
		if (nlc->msgcap & (1LL << type)) {
			skb = skb_copy(msg, GFP_KERNEL);
			if (!skb)  {
				rc = -ENOBUFS;
				goto out;
			}
			rc = genlmsg_unicast(nlc->net, skb, nlc->pid);
			if (rc == 0)
				good++;
		}
	}
	rc = 0;
out:
	mutex_unlock(&vdev->ngate);
	nlmsg_free(msg);
	if (good)
		return good;
	return rc;
}

#ifdef notdef
struct sk_buff *vfio_nl_new_reply(struct genl_info *info,
		int flags, u8 req)
{
	void *hdr;
	struct sk_buff *msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);

	if (!msg)
		return NULL;

	hdr = genlmsg_put_reply(msg, info,
			&vfio_nl_family, flags, req);
	if (!hdr) {
		nlmsg_free(msg);
		return NULL;
	}

	return msg;
}

int vfio_nl_reply(struct sk_buff *msg, struct genl_info *info)
{
	/* XXX: nlh is right at the start of msg */
	void *hdr = genlmsg_data(NLMSG_DATA(msg->data));

	if (genlmsg_end(msg, hdr) < 0)
		goto out;

	return genlmsg_reply(msg, info);
out:
	nlmsg_free(msg);
	return -ENOBUFS;
}
#endif


static const struct nla_policy vfio_nl_reg_policy[VFIO_NL_ATTR_MAX+1] = {
	[VFIO_ATTR_MSGCAP]	= { .type = NLA_U64 },
	[VFIO_ATTR_PCI_DOMAIN]	= { .type = NLA_U32 },
	[VFIO_ATTR_PCI_BUS]	= { .type = NLA_U16 },
	[VFIO_ATTR_PCI_SLOT]	= { .type = NLA_U8 },
	[VFIO_ATTR_PCI_FUNC]	= { .type = NLA_U8 },
};

static struct vfio_dev *vfio_nl_get_vdev(struct genl_info *info)
{
	u32 domain;
	u16 bus;
	u8 slot, func;
	u16 devfn;
	struct pci_dev *pdev;
	struct vfio_dev *vdev;

	domain = nla_get_u32(info->attrs[VFIO_ATTR_PCI_DOMAIN]);
	bus = nla_get_u16(info->attrs[VFIO_ATTR_PCI_BUS]);
	slot = nla_get_u8(info->attrs[VFIO_ATTR_PCI_SLOT]);
	func = nla_get_u8(info->attrs[VFIO_ATTR_PCI_FUNC]);
	devfn = PCI_DEVFN(slot, func);
	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (!pdev)
		return NULL;
	vdev = pci_get_drvdata(pdev);
	if (!vdev)
		return NULL;
	if (vfio_validate(vdev))
		return NULL;
	if (vdev->pdev != pdev || strncmp(vdev->name, "vfio", 4))
		return NULL;
	return vdev;
}

/*
 * The user driver must register here with a bitmask of which
 * events it is interested in receiving
 */
static int vfio_nl_user_register(struct sk_buff *skb, struct genl_info *info)
{
	u64 msgcap;
	struct list_head *pos;
	struct vfio_nl_client *nlc;
	int rc = 0;
	struct vfio_dev *vdev;

	msgcap = nla_get_u64(info->attrs[VFIO_ATTR_MSGCAP]);
	if (msgcap == 0)
		return -EINVAL;
	vdev = vfio_nl_get_vdev(info);
	if (!vdev)
		return -EINVAL;

	mutex_lock(&vdev->ngate);
	list_for_each(pos, &vdev->nlc_list) {
		nlc = list_entry(pos, struct vfio_nl_client, list);
		if (nlc->pid == info->snd_pid &&
		    nlc->net == info->_net)	/* already here */
			goto update;
	}
	nlc = kzalloc(sizeof(struct vfio_nl_client), GFP_KERNEL);
	if (!nlc) {
		rc = -ENOMEM;
		goto out;
	}
	nlc->pid = info->snd_pid;
	nlc->net = info->_net;
	list_add(&nlc->list, &vdev->nlc_list);
update:
	nlc->msgcap = msgcap;
out:
	mutex_unlock(&vdev->ngate);
	return rc;
}

static const struct nla_policy vfio_nl_err_policy[VFIO_NL_ATTR_MAX+1] = {
	[VFIO_ATTR_ERROR_HANDLING_REPLY] = { .type = NLA_U32 },
	[VFIO_ATTR_PCI_DOMAIN]	= { .type = NLA_U32 },
	[VFIO_ATTR_PCI_BUS]	= { .type = NLA_U16 },
	[VFIO_ATTR_PCI_SLOT]	= { .type = NLA_U8 },
	[VFIO_ATTR_PCI_FUNC]	= { .type = NLA_U8 },
};

static int vfio_nl_error_handling_reply(struct sk_buff *skb,
					struct genl_info *info)
{
	u32 value, seq;
	struct vfio_dev *vdev;

	value = nla_get_u32(info->attrs[VFIO_ATTR_ERROR_HANDLING_REPLY]);
	vdev = vfio_nl_get_vdev(info);
	if (!vdev)
		return -EINVAL;
	seq = nlmsg_hdr(skb)->nlmsg_seq;
	if (seq > vdev->nl_reply_seq) {
		vdev->nl_reply_value = value;
		vdev->nl_reply_seq = seq;
		wake_up(&vdev->nl_wait_q);
	}
	return 0;
}

static const struct nla_policy vfio_nl_pm_policy[VFIO_NL_ATTR_MAX+1] = {
	[VFIO_ATTR_PM_SUSPEND_REPLY] = { .type = NLA_U32 },
	[VFIO_ATTR_PCI_DOMAIN]	= { .type = NLA_U32 },
	[VFIO_ATTR_PCI_BUS]	= { .type = NLA_U16 },
	[VFIO_ATTR_PCI_SLOT]	= { .type = NLA_U8 },
	[VFIO_ATTR_PCI_FUNC]	= { .type = NLA_U8 },
};

static int vfio_nl_pm_suspend_reply(struct sk_buff *skb, struct genl_info *info)
{
	u32 value;
	struct vfio_dev *vdev;

	value = nla_get_u32(info->attrs[VFIO_ATTR_PM_SUSPEND_REPLY]);
	vdev = vfio_nl_get_vdev(info);
	if (!vdev)
		return -EINVAL;
	if (vdev->listeners == 0)
		return -EINVAL;
	vfio_pm_process_reply(value);
	return 0;
}

void vfio_nl_freeclients(struct vfio_dev *vdev)
{
	struct list_head *pos, *pos2;
	struct vfio_nl_client *nlc;

	mutex_lock(&vdev->ngate);
	list_for_each_safe(pos, pos2, &vdev->nlc_list) {
		nlc = list_entry(pos, struct vfio_nl_client, list);
		list_del(&nlc->list);
		kfree(nlc);
	}
	mutex_unlock(&vdev->ngate);
}

static struct genl_ops vfio_nl_reg_ops = {
	.cmd	= VFIO_MSG_REGISTER,
	.doit	= vfio_nl_user_register,
	.policy	= vfio_nl_reg_policy,
};

static struct genl_ops vfio_nl_err_ops = {
	.cmd	= VFIO_MSG_ERROR_HANDLING_REPLY,
	.doit	= vfio_nl_error_handling_reply,
	.policy	= vfio_nl_err_policy,
};

static struct genl_ops vfio_nl_pm_ops = {
	.cmd	= VFIO_MSG_PM_SUSPEND_REPLY,
	.doit	= vfio_nl_pm_suspend_reply,
	.policy	= vfio_nl_pm_policy,
};

int vfio_nl_init(void)
{
	int rc;

	rc = genl_register_family(&vfio_nl_family);
	if (rc)
		goto fail;

	rc = genl_register_ops(&vfio_nl_family, &vfio_nl_reg_ops);
	if (rc < 0)
		goto fail;
	rc = genl_register_ops(&vfio_nl_family, &vfio_nl_err_ops);
	if (rc < 0)
		goto fail;
	rc = genl_register_ops(&vfio_nl_family, &vfio_nl_pm_ops);
	if (rc < 0)
		goto fail;
	return 0;

fail:
	genl_unregister_family(&vfio_nl_family);
	return rc;
}

void vfio_nl_exit(void)
{
	genl_unregister_family(&vfio_nl_family);
}

int vfio_nl_remove(struct vfio_dev *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	struct sk_buff *msg;
	int rc;

	msg = vfio_nl_create(VFIO_MSG_REMOVE);
	if (!msg)
		return -ENOBUFS;

	NLA_PUT_U32(msg, VFIO_ATTR_PCI_DOMAIN, pci_domain_nr(pdev->bus));
	NLA_PUT_U16(msg, VFIO_ATTR_PCI_BUS, pdev->bus->number);
	NLA_PUT_U8(msg, VFIO_ATTR_PCI_SLOT, PCI_SLOT(pdev->devfn));
	NLA_PUT_U8(msg, VFIO_ATTR_PCI_FUNC, PCI_FUNC(pdev->devfn));

	rc = vfio_nl_mcast(vdev, msg, VFIO_MSG_REMOVE);
	if (rc > 0)
		rc = 0;
	return rc;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

int vfio_nl_upcall(struct vfio_dev *vdev, u8 type, int state, int waitret)
{
	struct pci_dev *pdev = vdev->pdev;
	struct sk_buff *msg;
	u32 seq;

	msg = vfio_nl_create(type);
	if (!msg)
		goto null_out;
	seq = nlmsg_hdr(msg)->nlmsg_seq;

	NLA_PUT_U32(msg, VFIO_ATTR_PCI_DOMAIN, pci_domain_nr(pdev->bus));
	NLA_PUT_U16(msg, VFIO_ATTR_PCI_BUS, pdev->bus->number);
	NLA_PUT_U8(msg, VFIO_ATTR_PCI_SLOT, PCI_SLOT(pdev->devfn));
	NLA_PUT_U8(msg, VFIO_ATTR_PCI_FUNC, PCI_FUNC(pdev->devfn));

	if (type == VFIO_MSG_ERROR_DETECTED)
		NLA_PUT_U32(msg, VFIO_ATTR_CHANNEL_STATE, state);

	if (vfio_nl_mcast(vdev, msg, type) <= 0)
		goto null_out;
	if (!waitret)
		return 0;

	/* sleep for reply */
	if (wait_event_interruptible_timeout(vdev->nl_wait_q,
	    (vdev->nl_reply_seq >= seq), VFIO_ERROR_REPLY_TIMEOUT) <= 0) {
		printk(KERN_ERR "vfio upcall timeout\n");
		goto null_out;
	}
	if (seq != vdev->nl_reply_seq)
		goto null_out;
	return vdev->nl_reply_value;

nla_put_failure:
	nlmsg_free(msg);
null_out:
	return -1;
}

/* the following routines invoked for pci error handling */

pci_ers_result_t vfio_error_detected(struct pci_dev *pdev,
					pci_channel_state_t state)
{
	struct vfio_dev *vdev = pci_get_drvdata(pdev);
	int ret;

	ret = vfio_nl_upcall(vdev, VFIO_MSG_ERROR_DETECTED, (int)state, 1);
	if (ret >= 0)
		return ret;
	return PCI_ERS_RESULT_NONE;
}

pci_ers_result_t vfio_mmio_enabled(struct pci_dev *pdev)
{
	struct vfio_dev *vdev = pci_get_drvdata(pdev);
	int ret;

	ret = vfio_nl_upcall(vdev, VFIO_MSG_MMIO_ENABLED, 0, 1);
	if (ret >= 0)
		return ret;
	return PCI_ERS_RESULT_NONE;
}

pci_ers_result_t vfio_link_reset(struct pci_dev *pdev)
{
	struct vfio_dev *vdev = pci_get_drvdata(pdev);
	int ret;

	ret = vfio_nl_upcall(vdev, VFIO_MSG_LINK_RESET, 0, 1);
	if (ret >= 0)
		return ret;
	return PCI_ERS_RESULT_NONE;
}

pci_ers_result_t vfio_slot_reset(struct pci_dev *pdev)
{
	struct vfio_dev *vdev = pci_get_drvdata(pdev);
	int ret;

	ret = vfio_nl_upcall(vdev, VFIO_MSG_SLOT_RESET, 0, 1);
	if (ret >= 0)
		return ret;
	return PCI_ERS_RESULT_NONE;
}

void vfio_error_resume(struct pci_dev *pdev)
{
	struct vfio_dev *vdev = pci_get_drvdata(pdev);

	(void) vfio_nl_upcall(vdev, VFIO_MSG_ERROR_RESUME, 0, 0);
}
