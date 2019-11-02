#include <linux/module.h>

/* We're using sysfs which is a GPL-only interface */
MODULE_LICENSE("GPL");

#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#define DRIVER_NAME "msg"

enum state {
	STATE_READY, /* Client can perform a new call */
	STATE_SEND, /* Blocking until server receives data */
	STATE_REPLY, /* Blocking until server replies */
	STATE_FINISHED, /* Client can pick up the reply */
	STATE_FAILED, /* Client is notified that server is gone */
};

enum {
	MSGTYPE_REQUEST,
	MSGTYPE_REPLY,
};


struct msg {
	int msgtype;
	int pid; /* endpoint identification */
	
	struct {
		char data[64];
	} payload;
};

struct endpoint {
	/* Bookkeeping */
	struct msgdev *device;
	struct task_struct *task;
	struct hlist_node node;

	/* Client */
	enum state state; /* client state */
	struct endpoint *server; /* target server */
	struct msg message; /* request & reply store */

	/* Server */
	struct endpoint *client; /* pending request from client, cleared on receive */
};

struct msgdev {
	struct device dev;
	struct cdev cdev;
	int written;
	struct page *page;
	unsigned long offset;
	size_t size;
	DECLARE_HASHTABLE(endpoints, 5);

	struct mutex lock;
};

#define SIZE 64

const char *msg_state_str(enum state state)
{
	switch (state) {
	case STATE_READY:
		return "client-ready";
	case STATE_SEND:
		return "client-send";
	case STATE_REPLY:
		return "client-reply";
	case STATE_FINISHED:
		return "client-finished";
	case STATE_FAILED:
		return "client-failed";

	}
	return "unknown";
}

bool msg_state_check(struct endpoint *endpoint, enum state state)
{
	if (endpoint->state != state) {
		pr_err("Expected endpoint state is %s, actual %s.\n", msg_state_str(state), msg_state_str(endpoint->state));
		return false;
	}

	return true;
}

void msg_state_set(struct endpoint *endpoint, enum state state)
{
	pr_info("Switching %d from %s to %s.\n",
		endpoint->task->pid, msg_state_str(endpoint->state), msg_state_str(state));
	endpoint->state = state;
}

struct endpoint *msg_endpoint_get(struct msgdev *device, int pid)
{
	struct endpoint *endpoint;

	hash_for_each_possible(device->endpoints, endpoint, node, pid)
		if (endpoint->task->pid == pid)
			return endpoint;

	return NULL;
}

void msg_sleep(struct endpoint *client)
{
	set_current_state(TASK_INTERRUPTIBLE);

	mutex_unlock(&client->device->lock);
	schedule();
	mutex_lock(&client->device->lock);
}

/* Client sends a request and waits for reply */
/* TODO: Switch prototype to msg_send(client, server, smsg, rmsg)
 *       (where server enpoint lookup happens before the call to this func)
 */
int msg_send(struct endpoint *client, const struct msg *usermsg)
{
	pr_debug("msg_send: src=%d state=%s", client->task->pid, msg_state_str(client->state));

	if (!msg_state_check(client, STATE_READY))
		return -EINVAL;

	if (copy_from_user(&client->message, usermsg, sizeof client->message) != 0)
		return -EINVAL;

	printk("request: %d -> %d\n", client->task->pid, client->message.pid);

	msg_state_set(client, STATE_SEND);

	/* Link from client to server */
	WARN_ON(client->server);
	client->server = msg_endpoint_get(client->device, client->message.pid);
	if (!client->server)
		return -EINVAL;

	/* Rewrite pid for the server */
	client->message.pid = client->task->pid;

	if (client->server->client)
	       /* TODO: Wait for another client */
		return -EWOULDBLOCK;

	/* Link from server to client */
	WARN_ON(client->server->client);
	client->server->client = client;

	/* Wake up a sleeping server */
	wake_up_process(client->server->task);

	/* Wait for the server to receive the data */
	msg_state_set(client, STATE_SEND);
	while (client->state == STATE_SEND) {
		msg_sleep(client);
		if (signal_pending(current))
			return -EINTR;
	}

	switch (client->state) {
	case STATE_REPLY:
	case STATE_FINISHED:
		/* Server received message */
		break;
	case STATE_FAILED:
		/* Server quit */
		WARN_ON(client->server);

		msg_state_set(client, STATE_READY);
		return -EINVAL;
	default:
		WARN_ON(true);
		return -EINVAL;
	}

	/* state == STATE_REPLY */
	while (client->state == STATE_REPLY) {
		msg_sleep(client);
		if (signal_pending(current))
			return -EINTR;
	}
	switch (client->state) {
	case STATE_FINISHED:
		/* Server replied */
		break;
	case STATE_FAILED:
		/* Server quit */
		WARN_ON(client->server);

		msg_state_set(client, STATE_READY);
		return -EINVAL;
	default:
		WARN_ON(true);
		return -EINVAL;
	}

	return 0;
}

/* Server receives the request */
int msg_receive(struct endpoint *server, struct msg __user *usermsg)
{
	/* Reading in STATE_FINISHED is reserved to client, other states
	 * are blocking (either with mutex locked or waiting in
	 * TASK_KILLABLE process state).
	 */
	WARN_ON(server->state != STATE_READY);

	/* TODO: Wait for the client */
	if (!server->client) {
		msg_sleep(server);
		if (signal_pending(current))
			return -EINTR;
	}

	WARN_ON(server->client->server != server);
	WARN_ON(server->client->state != STATE_SEND);

	if (copy_to_user(usermsg, &server->client->message, sizeof server->client->message) != 0)
		return -EINVAL;

	/* Notify client & unlink */
	msg_state_set(server->client, STATE_REPLY);
	wake_up_process(server->client->task);
	/* server->client->server still pointing to server to enable cleanup */
	server->client = NULL;

	return 0;
}

/* Server sends reply */
/* TODO: Switch prototype to msg_reply(server, client, rmsg)
 *       (where server enpoint lookup happens before the call to this func)
 */
int msg_reply(struct endpoint *server, const struct msg __user *usermsg)
{
	struct endpoint *client;
	int pid;

	get_user(pid, &usermsg->pid);

	client = msg_endpoint_get(server->device, pid);

	pr_debug("reply: %d -> %d (%p)\n", current->pid, pid, client);

	/* Check whether client still exists */
	if (!client)
		return -EINVAL;
	/* Check for bogus reply from server */
	if (client->server != server)
		return -EINVAL;
	if (!msg_state_check(client, STATE_REPLY))
		return -EINVAL;
	/* Now we know that client expects a reply from this server */

	if (copy_from_user(&client->message, usermsg, sizeof *usermsg) != 0)
		return -EINVAL;

	/* Notify client & unlink */
	msg_state_set(client, STATE_FINISHED);
	wake_up_process(client->task);
	client->server = NULL;
	/* Now the client and server are completely decoupled */

	return 0;
}

int msg_open(struct inode *inode, struct file *file)
{
	struct msgdev *device = container_of(inode->i_cdev, struct msgdev, cdev);
	struct endpoint *endpoint;
	int ret = 0;

	printk("open %p %p\n", inode, file);

	endpoint = kzalloc(sizeof *endpoint, GFP_KERNEL);
	if (!endpoint)
		return -ENOMEM;

	endpoint->device = device;
	endpoint->task = current;

	mutex_lock(&device->lock);

	/* Register endpoint */
	if (msg_endpoint_get(device, current->pid)) {
		ret = -EBUSY;
		goto out;
	}
	hash_add(device->endpoints, &endpoint->node, current->pid);

out:
	mutex_unlock(&device->lock);

	file->private_data = endpoint;

	printk("open finished (pid=%d)\n", current->pid);

	return ret;
}

int msg_release(struct inode *inode, struct file *file)
{
	struct endpoint *endpoint = file->private_data;
	struct endpoint *client;
	int bkt;

	printk("release %p %p\n", inode, file);

	endpoint = file->private_data;

	mutex_lock(&endpoint->device->lock);

	WARN_ON(endpoint->task != current);

	/* Unregister endpoint */
	hash_del(&endpoint->node);

	/* Client: Notify the server TODO: is this needed at all? */
	if (endpoint->server) {
		endpoint->server->client = NULL;
		endpoint->server = NULL;
	}

	/* Server: Notify all clients */
	hash_for_each(endpoint->device->endpoints, bkt, client, node) {
		if (client->server == endpoint) {
			msg_state_set(client, STATE_FAILED);
			client->server = NULL;
			wake_up_process(client->task);
		}
	}

	/* All references to endpoint have been removed */
	mutex_unlock(&endpoint->device->lock);

	kfree(endpoint);

	printk("released (pid=%d)\n", current->pid);

	return 0;
}


ssize_t msg_write(struct file *file, const char __user *buf, size_t size, loff_t *y)
{
	struct endpoint *endpoint = file->private_data;
	const struct msg __user *usermsg = (const struct msg __user *) buf;
	int ret = -EINVAL;
	int msgtype;

	pr_debug("write: size=%d\n", (int) size);

	if (size != sizeof (const struct msg))
		return ret;

	get_user(msgtype, &usermsg->msgtype);

	mutex_lock(&endpoint->device->lock);

	switch (msgtype) {
	case MSGTYPE_REQUEST:
		/* Client sends requests and waits for reply */
		ret = msg_send(endpoint, usermsg);
		break;
	case MSGTYPE_REPLY:
		ret = msg_reply(endpoint, usermsg);
		break;
	}

	mutex_unlock(&endpoint->device->lock);

	return ret ?: sizeof usermsg;
}

ssize_t msg_read(struct file *file, char *buf, size_t size, loff_t *y)
{
	struct endpoint *endpoint = file->private_data;
	struct msg __user *usermsg = (struct msg __user *) buf;
	int ret = -EINVAL;

	if (size != sizeof (const struct msg))
		return ret;

	mutex_lock(&endpoint->device->lock);

	switch (endpoint->state) {
	case STATE_READY:
		/* No client exchange running => server reads data */
		ret = msg_receive(endpoint, usermsg);
		break;
	case STATE_FINISHED:
		/* Client reads after writing => call returns */
		ret = copy_to_user(usermsg, &endpoint->message, sizeof endpoint->message) ? -EINVAL : 0;
		msg_state_set(endpoint, STATE_READY);
		/* Client is now ready to perform a new call */
		break;
	default:
		WARN_ON(true);
		ret = -EINVAL;
	}

	mutex_unlock(&endpoint->device->lock);

	return ret ?: size;
}

long msg_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	struct endpoint *endpoint = file->private_data;

	return -EINVAL;

	mutex_lock(&endpoint->device->lock);
	mutex_unlock(&endpoint->device->lock);

	return 0;
}

struct file_operations msg_fops = {
	.owner = THIS_MODULE,
	.open = msg_open,
	.release = msg_release,
	.write = msg_write,
	.read = msg_read,
	.unlocked_ioctl = msg_ioctl,
};

struct msgdev device;

int msg_init(void)
{
	int err = -1;

	device_initialize(&device.dev);
	device.dev.init_name = "msg";
	cdev_init(&device.cdev, &msg_fops);
	mutex_init(&device.lock);
	hash_init(device.endpoints);

	if (!(device.dev.class = class_create(THIS_MODULE, "msg"))) {
		pr_err("class\n");
		goto err_class;
	}

	if (alloc_chrdev_region(&device.dev.devt, 0, 2, DRIVER_NAME) < 0) {
		pr_err("chrdev\n");
		goto err_chrdev;
	}

	printk("%p %p %x\n", &device.cdev, &device.dev, device.dev.devt);
	if ((err = cdev_device_add(&device.cdev, &device.dev)) < 0) {
		pr_err("cdev_device_add\n");
		goto err_cdev;
	}

	/*if (!(device.chardev = device_create(cl, NULL, device.devt, NULL, "msg%d", 0))) {
		pr_err("device_create\n");
		goto err_device;
	}*/

	return 0;

	//device_del(device.chardev);
//err_device:
//	cdev_device_del(&device.cdev, &device.dev);
err_cdev:
	unregister_chrdev_region(device.dev.devt, 1);
err_chrdev:
	class_destroy(device.dev.class);
err_class:
	return err;
}

void msg_exit(void)
{
	cdev_device_del(&device.cdev, &device.dev);
	unregister_chrdev_region(device.dev.devt, 1);
	class_destroy(device.dev.class);
}

module_init(msg_init);
module_exit(msg_exit);

