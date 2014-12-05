/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>

#include "sniffer_ioctl.h"

MODULE_AUTHOR("");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain = NF_INET_PRE_ROUTING;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;
struct nf_hook_ops nf_hook_ops_out;
static int hook_chain_out = NF_INET_POST_ROUTING;

struct semaphore sem;
wait_queue_head_t queue;
hash_table * table;

//To test GET /courses/2014fa/cs5413/labs/big
#define SIGNATURE "30000"

struct node {
	struct list_head list;
	uint32_t src_ip;
	uint32_t dest_ip;
	uint16_t src_port;
	uint16_t dest_port;
	int action;
	int direction;
	int proto;
};

FLAG check_flag(struct tcphdr *tcph) {
	FLAG cur_flag = INIT;
	if (tcph->syn) {
		if (tcph->ack)
			cur_flag = SYNACK;
		else
			cur_flag = SYN;
	}
	else if (tcph->ack)
		cur_flag = ACK;
	else if (tcph->rst)
		cur_flag = RST;
	else if (tcph->fin)
		cur_flag = FIN;
	return cur_flag;
}

u_int hash_function(table_key * key) {
	return key->src_ip ^ key->dst_ip ^ key->src_port ^ key->dst_port;
}

hash_table * create_hash_table(int size) {
	hash_table * table = (hash_table *) kmalloc (sizeof(hash_table), GFP_ATOMIC);
	memset(table, 0, sizeof(hash_table));
	table->size = size;
	table->occupied = 0;
	table->head = (linked_list **) vmalloc (sizeof(linked_list) * size);
	memset(table->head, 0, sizeof(linked_list));
	int i = 0;
	for (; i < size; i++) {
		table->head[i] = NULL;
	}
	return table;
}

void * find_key(linked_list * head, table_key * key, FLAG f) {
	table_key * cur = head->list;
	while (cur != NULL) {
		if (f == SYN || f == ACK || f == RST || f == FIN) {
			//printk("SYN packet");
			if (cur->src_ip == key->src_ip && cur->dst_ip == key->dst_ip && cur->src_port == key->src_port && cur->dst_port == key->dst_port && cur-> proto == key->proto) {
				//printk("in match\n");
				return cur;
			}
		}
		if (f == SYNACK || f == RST || f == FIN) {
			if (cur->src_ip == key->dst_ip && cur->dst_ip == key->src_ip && cur->src_port == key->dst_port && cur->dst_port == key->src_port && cur-> proto == key->proto) {
				//printk("out match\n");
				return cur;
				}
		}
		//if (f != SYN && f != SYNACK && f != ACK &&)
		cur = cur->next;
	}
	return NULL;
}

table_key * insert_into_list(linked_list * list, table_key * key, FLAG f) {
	table_key * found = find_key(list, key, f);
	if (found == NULL) {
		found = (table_key *)kmalloc (sizeof(table_key), GFP_ATOMIC);
		memset(found, 0, sizeof(table_key));
		found->src_ip = key->src_ip;
		found->dst_ip = key->dst_ip;
		found->src_port = key->src_port;
		found->dst_port = key->dst_port;
		found->state = key->state;
		found->proto = key->proto;
		found->next = list->list;
		list->list = found;
		printk("Inserted into table\n");
		return NULL;
	}
	return found;
}

table_key * insert_into_table(hash_table * table, table_key * key, FLAG f) {
	u_int hash = hash_function(key) % table->size;
	if (table->head[hash] == NULL) {
		linked_list * list = (linked_list *) kmalloc (sizeof(linked_list), GFP_ATOMIC);
		memset(list, 0, sizeof(linked_list));
		list->list = NULL;
		table->head[hash] = list;
	}
	table_key * found = insert_into_list(table->head[hash], key, f);
	if (found != NULL)
		return found;
	table->occupied ++;
	return NULL;
}

table_key * find(hash_table * table, table_key * key, FLAG f) {
	u_int hash = hash_function(key) % table->size;
	if (table->head[hash] == NULL)
		return NULL;
	hash_table * test = find_key(table->head[hash], key, f);
	/*if (test == NULL)
		printk("shabi");*/
	return test;
}



// skb buffer between kernel and user space
struct list_head skbs;
struct list_head buffer;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

static inline struct udphdr * ip_udp_hdr(struct iphdr *iph)
{
    struct udphdr *udph = (void *) iph + iph->ihl*4;
    return udph;
}

/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	if (atomic_read(&refcnt) > 0)
		return -EBUSY;
	atomic_set(&refcnt, 1); 
    wait_event_interruptible(queue,!list_empty(&buffer));
	struct skb_list * tmp;
    int res = -1;
    if (list_empty(&buffer)) {
		atomic_set(&refcnt, 0);
		return -1;
	} 
    tmp = list_entry(buffer.next, struct skb_list, list);
    res = tmp->skb->len;
    copy_to_user(buf, tmp->skb->data, tmp->skb->len);

    down_interruptible(&sem); 
    list_del(buffer.next);
    up(&sem);
	atomic_set(&refcnt, 0);
    printk(KERN_DEBUG "%d Byte\n", res);
    return res;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static void insert(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, int action, int direction, int proto) {
	struct node * node;
	int found = 0;
	list_for_each_entry(node, &skbs, list) {
		if (node->src_ip == src_ip && node->dest_ip == dest_ip && node->src_port == src_port && node->dest_port == dest_port&& node->direction == direction && node->proto == proto) {
			found = 1;
			break;
		}			
	}
	if (found == 0) {
		node = (struct node *) vmalloc (sizeof(struct node));
		node->src_ip = src_ip;
		node->dest_ip = dest_ip;
		node->src_port = src_port;
		node->dest_port = dest_port;
		node->action = action;
		node->direction = direction;
		node->proto = proto;
		list_add(&node->list, &skbs);
		printk("Adding new node\n");
	}
	else {
		node->action = action;
		printk("updating action or mode\n");
	}
}

static void delete(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, int direction, int proto) {
	struct node * node;
	int found = 0;
	list_for_each_entry(node, &skbs, list) {
		if (node->src_ip == src_ip && node->dest_ip == dest_ip && node->src_port == src_port && node->dest_port == dest_port && node->direction == direction && node->proto == proto) {
			found = 1;
			break;
		}
	}
	if (found == 1) {
		list_del(node);
		printk("Node deleted++++\n");
	}
	else
		printk("No such node, disable unaffected\n");
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
	//printk("%d==============\n", cmd);
	struct sniffer_flow_entry * flow = (struct sniffer_flow_entry *) arg;
	//printk("src ip: %d, dest ip: %d, src port: %d, dest port: %d, action: %d, mode: %d", flow->src_ip, flow->dest_ip, flow->src_port, flow->dest_port, flow->action, flow->mode);
    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;

    switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
        insert(flow->src_ip, flow->dest_ip, flow->src_port, flow->dest_port, flow->action, flow->direction, flow->proto);
		printk("Enable");
        break;
    case SNIFFER_FLOW_DISABLE:
        //insert(flow->src_ip, flow->dest_ip, flow->src_port, flow->dest_port, flow->action, 0);
		delete(flow->src_ip, flow->dest_ip, flow->src_port, flow->dest_port, flow->direction, flow->proto);
		printk("Disable");
        break;
    default:
        printk(KERN_DEBUG "Unknown command\n");
        err = -EINVAL;
    }

    return err;
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};

static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = ip_udp_hdr(iph);
		if (ntohs(udph->dest) == 53)
			return NF_ACCEPT;
		if (ntohs(udph->source) == 53)
			return NF_ACCEPT;
		return NF_DROP;
	}
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
		//printk("src ip: %d, dest ip: %d, src port: %d, dest port: %d, action: %d, mode: %d", iph->saddr, ntohl(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));

        if (ntohs(tcph->dest) == 22)
            return NF_ACCEPT;

        if (ntohs(tcph->dest) != 22) {
			FLAG f = check_flag(tcph);
			if (f == SYN)			
			printk("1111\n");
			if (f == SYNACK)
			printk("2222\n");
			if (f == ACK)
			printk("3333\n");

			table_key * key = (table_key *) kmalloc (sizeof(table_key), GFP_ATOMIC);
			memset(key, 0, sizeof(table_key));
			key->src_ip = ntohl(iph->saddr);
			key->dst_ip = ntohl(iph->daddr);
			key->src_port = ntohs(tcph->source);
			key->dst_port = ntohs(tcph->dest);
			key->proto = 0;
			key->state = 0;
			key->next = NULL;
			table_key * cur = find(table, key, f);
			// after SYN 0
			// after SYNACK 1
			if (cur != NULL) {
				/*if (cur->state == 0) {
					//printk("at 0 state\n");
					if (f == FIN || f == ACK) 
						return NF_DROP;
					else if (f == SYN)
						return NF_ACCEPT;
					else if (f == SYNACK) {
						cur->state = 1;
						return NF_ACCEPT;
					}
					else
						return NF_ACCEPT;
				}
				if (cur->state == 1) {
					printk("at state 1\n");
					if (f == SYN || f == FIN)
						return NF_DROP;
					else if (f == ACK) {
						cur->state = 2;
						return NF_ACCEPT;
					}
					else if (f == RST) {
						cur->state = 0;
						return NF_ACCEPT;
					}
					else
						return NF_ACCEPT;
				}
				if (cur->state == 2) {
					printk("at state 2\n");
					if (f == SYN || f == SYNACK) {
						printk("SYN/SYNACK\n");
						return NF_DROP;
					}
					else if (f == FIN) {
						cur->state = 3;
						return NF_ACCEPT;
					}
					else if (f == RST) {
						printk("RST");
						cur->state = 0;
						return NF_ACCEPT;
					}
					else {
						printk("ACK");
						return NF_ACCEPT;
					}
				}
				if (cur->state == 3) {
					printk("at state 3\n");
					if (f == FIN) {
						cur->state = 4;
						return NF_ACCEPT;
					}
					else if (f == RST) {
						cur->state = 0;
						return NF_ACCEPT;
					}
					else
						return NF_DROP;
				}
				if (cur->state == 4) {
					printk("at state 4\n");
					if (f == SYN) {
						// TODO
						cur->state = 0;
						return NF_ACCEPT;
					}
					else
						return NF_DROP;
				}*/
				return NF_ACCEPT;
			}
			else {
				printk("not in hash table\n");
            	struct node * node;
				list_for_each_entry(node, &skbs, list) {
					if ((node->src_ip == ntohl(iph->saddr) || node->src_ip == 0) && (node->dest_ip == ntohl(iph->daddr) || node->dest_ip == 0) && (node->src_port == ntohs(tcph->source) || node->src_port == 0) && (node->dest_port == ntohs(tcph->dest) || node->dest_port == 0) && (node->proto == 0)) {
								if (node->action == SNIFFER_ACTION_CAPTURE) {
									struct skb_list * temp= (struct skb_list *) kmalloc (sizeof(struct skb_list), GFP_ATOMIC);
									temp->skb=skb_copy(skb, GFP_ATOMIC);
									down_interruptible(&sem);
									list_add_tail(&temp->list, &buffer);
									up(&sem);
									wake_up_interruptible(&queue);
								}
								if (node->action == SNIFFER_ACTION_DPI) {
									struct ip_hdr_t * ip_h = skb->data;
									int ip_len =IP_HL(ip_h) * 4;
									struct tcp_hdr_t * tcp_h = ip_h + ip_len;
									char * data = skb->data + ip_len + sizeof(struct tcp_hdr_t);
									int data_len = skb->len - ip_len - sizeof(struct tcp_hdr_t);
									int i, j;
									int flag = 0;
									int sig_len=strlen(SIGNATURE);
									for (i = 0; i < data_len - sig_len; i++) {
										flag = 1;
										for (j = 0;j < sig_len; j++) {
											if (data[i + j] != SIGNATURE[j]) {
												flag = 0;
												break;
											}
										}
										if (flag == 1) {
											delete(node->src_ip, node->dest_ip, node->src_port, node->dest_port, node->direction, node->proto);
											return NF_DROP;
										}
									}
								}
								insert_into_table(table, key, f);		
								//printk("Allowed\n");
								return NF_ACCEPT;
					}
				}
			}
        	printk(KERN_DEBUG "Rejected %d %x\n", ntohs(tcph->dest), iph->saddr);
        	return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;
    printk(KERN_DEBUG "sniffer_init\n"); 
	table = create_hash_table(600000);
    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;
        
    }

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skbs);
	INIT_LIST_HEAD(&buffer);
	init_waitqueue_head(&queue);
    sema_init(&sem, 1);

    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }

	memset(&nf_hook_ops_out, 0, sizeof(nf_hook_ops));
    nf_hook_ops_out.hook = sniffer_nf_hook;
    nf_hook_ops_out.pf = PF_INET;
    nf_hook_ops_out.hooknum = hook_chain_out;
    nf_hook_ops_out.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops_out);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook out failed\n");
        goto out_add;
    }

    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{

	if (nf_hook_ops_out.hook) {
        nf_unregister_hook(&nf_hook_ops_out);
        memset(&nf_hook_ops_out, 0, sizeof(nf_hook_ops));
    }
    
	if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
	printk(KERN_DEBUG "sniffer_exit\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);
