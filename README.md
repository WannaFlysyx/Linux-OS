# 题目内容
1、增加Linux系统调用  
2、实现基于模块的文件系统  
3、增加Linux驱动程序  
4、统计Linux系统缺页的次数  
5、进程/线程通信

# 前期准备
1、VMware Workstation pro 17、Ubuntu 20.04.2.0、Linux内核5.6.15  
2、内核存放在/usr/src目录下，使用默认的文件夹名/linux-5.6.15  
3、安装libncurses5-dev、libelf-dev、libssl-dev，命令：sudo apt install libncurses5-dev libelf-dev libssl-dev -y  
4、安装bc，命令：sudo apt install bc

# 内核编译方法
1、彻底清理内核源代码树，命令：make mrproper  
2、创建默认配置，使用图形化界面，无需修改直接保存，命令：make menuconfig  
3、在/linux-5.6.15文件夹中执行命令：make -j$(nproc)  
4、对模块进行编译，命令：make modules -j$(nproc)  
5、安装模块，命令：make INSTALL_MOD_STRIP=1 modules_install  
6、安装内核，命令：make INSTALL_MOD_STRIP=1 install  
7、关机重启，按住shift进入grub引导，选择新安装的内核开机

# 实验一-系统调用
1、在/linux-5.6.15/include/linux/syscalls.h文件中声明系统调用函数原型：asmlinkage long sys_cube(int num);  
2、在/linux-5.6.15/ kernel/sys.c文件中书写函数如下：
```
SYSCALL_DEFINE1(cube,long,num){
	long result = num*num*num;
	printk("The result is %ld.\n",result);
	return result;
}
```
3、在/linux-5.6.15/arch/x86/entry/syscalls/syscall_64.tbl文件中添加系统调用号：439 64	cube	__x64_sys_cube  
4、编写函数调用：
```
#include <stdio.h>
#include<linux/kernel.h>
#include<sys/syscall.h>
#include<unistd.h>
int main()
{
	long int a = syscall(439,3);
	printf("System call sys_cube Result is: %ld\n", a);
	return 0;
}
```

# 实验二-基于模块的文件系统
1、确保在之前make menuconfig里面设置的File systems里面的The Extended 4（ext4）filesystem前面的标号为M，表示允许ext4文件系统模块化加载。如不是则要重新编译内核  
2、将/linux-5.6.15/fs里面的/ext4文件夹整体复制出来到其他地方并改名成为ext4edit文件夹  
3、修改ext4edit文件夹下的Makefile文件，将全部的ext4均改成ext4edit  
4、打开ext4edit文件夹下的super.c，将ext4_fs_type结构体中的.name字段改成ext4edit；同时修改MODULE_ALIAS_FS()，将其中的名字改成ext4edit  
5、打开sysfs.c，修改ext4_init_sysfs函数中kobject_create_and_add函数中的第一个参数为ext4edit  
6、打开file.c，在ext4_file_write_iter函数中增加输出语句printk(“New ext4edit is used”);  
7、在ext4edit文件夹内使用make命令，之后使用sudo insmod ext4edit.ko命令安装相应的模块  
8、使用cd/dev后，使用sudo mknod -m 777 任意名字1 b 1 0  
9、使用cd/mnt后，sudo mkdir 任意名字2  
10、使用mount /dev/任意名字1 -t ext4edit /mnt/任意名字2  
11、使用df -T -h查看磁盘空间使用情况  
12、使用cd /mnt/任意名字2后，创建文件并输入内容保存后退出  
13、使用dmesg -c查看和控制内核环缓冲区  
14、使用sudo mount /mnt/任意名字2卸载文件系统

# 实验三-驱动程序
1、编写Makefile和任意设备名字.c文件  
Makefile代码如下：
```
obj-m += WannaFlydev.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
.c文件代码如下：
```
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <uapi/linux/hdreg.h>
#include <linux/atomic.h>

#define SUCCESS 0
#define SECTOR_SHIFT 9 //扇区大小2的9次方=512B
#define SECTOR_SIZE (1 << SECTOR_SHIFT)

static const char* my_dev_name = "任意名字";
static const size_t buffer_size = 64 * 1024 * PAGE_SIZE;

typedef struct {
    sector_t capacity;
    u8* data;
    atomic_t open_counter;
    struct blk_mq_tag_set tag_set;
    struct request_queue *queue;
    struct gendisk *disk;
} 任意名字_device;

static int major = 0;   //指示存储设备的主设备号
static 任意名字_device* device = NULL;  //设备的DCT

static int allocate_buffer(任意名字_device* dev) {
    dev->capacity = buffer_size >> SECTOR_SHIFT;
    dev->data = vmalloc(dev->capacity << SECTOR_SHIFT);
    return dev->data? SUCCESS : -ENOMEM;
}

static void free_buffer(任意名字_device* dev) {
    if (dev->data) {
        vfree(dev->data);
        dev->data = NULL;
        dev->capacity = 0;
    }
}

static void remove_device(void) {
    if (device) {
        if (device->disk) {
            del_gendisk(device->disk);
            put_disk(device->disk);
            device->disk = NULL;
        }
        if (device->queue) {
            blk_cleanup_queue(device->queue);
            device->queue = NULL;
        }
        if (device->tag_set.tags) {
            blk_mq_free_tag_set(&device->tag_set);
        }
        free_buffer(device);
        vfree(device);
        device = NULL;
    }
}

static int do_simple_request(struct request *rq, unsigned int *nr_bytes) {
    int ret = SUCCESS;
    struct bio_vec bvec;
    struct req_iterator iter;
    任意名字_device *dev = rq->q->queuedata;
    loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
    loff_t dev_size = (loff_t)(dev->capacity << SECTOR_SHIFT);

    rq_for_each_segment(bvec, rq, iter) {
        unsigned long b_len = bvec.bv_len;
        void* b_buf = page_address(bvec.bv_page) + bvec.bv_offset;
        if ((pos + b_len) > dev_size) {
            b_len = (unsigned long)(dev_size - pos);
        }
        if (rq_data_dir(rq)) {
            memcpy(dev->data + pos, b_buf, b_len);
        } else {
            memcpy(b_buf, dev->data + pos, b_len);
        }
        pos += b_len;
        *nr_bytes += b_len;
    }
    return ret;
}

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data* bd) {
    unsigned int nr_bytes = 0;
    blk_status_t status = BLK_STS_OK;
    struct request *rq = bd->rq;

    blk_mq_start_request(rq);
    if (do_simple_request(rq, &nr_bytes)!= SUCCESS) {
        status = BLK_STS_IOERR;
    }
    if (blk_update_request(rq, status, nr_bytes)) {
        BUG();
    }
    __blk_mq_end_request(rq, status);
    return BLK_STS_OK;
}

static struct blk_mq_ops mq_ops = {
  .queue_rq = queue_rq,
};

static int open(struct block_device *bdev, fmode_t mode) {
    任意名字_device* dev = bdev->bd_disk->private_data;
    if (dev) {
        atomic_inc(&dev->open_counter);
        return SUCCESS;
    }
    return -ENXIO;
}

static void release(struct gendisk *disk, fmode_t mode) {
    任意名字_device* dev = disk->private_data;
    if (dev) {
        atomic_dec(&dev->open_counter);
    }
}

static int getgeo(任意名字_device* dev, struct hd_geometry* geo) {
    sector_t quotient;

    geo->start = 0;
    if (dev->capacity > 63) {
        geo->sectors = 63;
        quotient = (dev->capacity + (63 - 1)) / 63;
        if (quotient > 255) {
            geo->heads = 255;
            geo->cylinders = (unsigned short)((quotient + (255 - 1)) / 255);
        } else {
            geo->heads = (unsigned char)quotient;
            geo->cylinders = 1;
        }
    } else {
        geo->sectors = (unsigned char)dev->capacity;
        geo->cylinders = 1;
        geo->heads = 1;
    }
    return SUCCESS;
}


static const struct block_device_operations fops = {
  .owner = THIS_MODULE,
  .open = open,
  .release = release,
};

static int add_device(void) {
    int ret = SUCCESS;
    任意名字_device* dev = kzalloc(sizeof(任意名字_device), GFP_KERNEL);
    if (!dev) {
        return -ENOMEM;
    }
    device = dev;

    ret = allocate_buffer(dev);
    if (ret) {
        return ret;
    }

    dev->tag_set.ops = &mq_ops;
    dev->tag_set.nr_hw_queues = 1;
    dev->tag_set.queue_depth = 128;
    dev->tag_set.numa_node = NUMA_NO_NODE;
    dev->tag_set.cmd_size = sizeof(void*);
    dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
    dev->tag_set.driver_data = dev;

    ret = blk_mq_alloc_tag_set(&dev->tag_set);
    if (ret) {
        return ret;
    }

    struct request_queue *queue = blk_mq_init_queue(&dev->tag_set);
    if (IS_ERR(queue)) {
        ret = PTR_ERR(queue);
        return ret;
    }
    dev->queue = queue;

    dev->queue->queuedata = dev;

    struct gendisk *disk = alloc_disk(1);
    if (!disk) {
        return -ENOMEM;
    }

    disk->flags |= GENHD_FL_NO_PART_SCAN;
    disk->flags |= GENHD_FL_REMOVABLE;
    disk->major = major;
    disk->first_minor = 0;
    disk->fops = &fops;
    disk->private_data = dev;
    disk->queue = dev->queue;
    sprintf(disk->disk_name, my_dev_name);
    set_capacity(disk, dev->capacity);

    dev->disk = disk;
    add_disk(disk);
    return ret;
}

static int __init init(void) {
    int ret = SUCCESS;
    major = register_blkdev(major, my_dev_name);
    if (major <= 0) {
        return -EBUSY;
    }

    ret = add_device();
    if (ret) {
        unregister_blkdev(major, my_dev_name);
    }
    return ret;
}

static void __exit my_exit(void) {
    remove_device();
    if (major > 0) {
        unregister_blkdev(major, my_dev_name);
    }
}

module_init(init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
```
2、编译安装后使用lsblk查看所有块设备  
3、使用sudo mkfs.ext4 /dev/任意名字对设备格式化后挂载到/mnt/任意名字文件夹上  
4、编写.c文件读取数据，代码如下：
```
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <string.h>

#define DEVICE_NAME "/dev/任意名字"

int main() {
    int fd;
    char buffer[1024];  // 定义一个较小的缓冲区用于示例

    // 打开块设备
    fd = open(DEVICE_NAME, O_RDWR);
    if (fd == -1) {
        perror("Failed to open device");
        return 1;
    }

    // 写入一些简单数据到块设备
    sprintf(buffer, "WannaFly");
    ssize_t bytes_written = write(fd, buffer, strlen(buffer));
    if (bytes_written == -1) {
        perror("Failed to write to device");
        close(fd);
        return 1;
    }

    // 将文件指针移动到设备开头
    lseek(fd, 0, SEEK_SET);

    // 从块设备读取数据并打印
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read == -1) {
        perror("Failed to read from device");
        close(fd);
        return 1;
    }
    buffer[bytes_read] = '\0';  // 添加字符串结束符
    printf("Read from device: %s\n", buffer);

    // 关闭设备
    close(fd);

    return 0;
}
```

# 实验四-统计缺页次数
1、在/linux-5.6.15/arch/x86/mm/fault.c中do_page_fault函数中good_area:后写入代码：pfcount++;  
2、在/linux-5.6.15/arch/x86/mm/fault.c中声明代码：unsigned long volatile pfcount;  
3、在/linux-5.6.15/ include/linux/mm.h中声明代码：extern unsigned long volatile pfcount;  
4、在/linux-5.6.15/kernel/kallsyms.c中添加代码：EXPORT_SYMBOL(pfcount);  
5、创建Makefile和.c文件  
Makefile代码如下：
```
ifneq ($(KERNELRELEASE),)
	obj-m:=readpfcount.o
else
	KDIR:= /lib/modules/$(shell uname -r)/build
	PWD:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
```
.c文件代码如下：
```
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <stdarg.h>

extern unsigned long volatile pfcount;
static struct timer_list test_timer;
static unsigned long pfcount_last;
static unsigned long pfcount_in_2;
static int count = 0;

MODULE_LICENSE("GPL");


/*5,实现show函数
  作用是将内核数据输出到用户空间
  将在proc file输出时被调用
  */
static int my_proc_show(struct seq_file *m, void *v)
{
    /*这里不能使用printfk之类的函数
      要使用seq_file输出的一组特殊函数
      */
	seq_printf(m, "[latest] Number of page fault interrupts in 2 seconds: %ld !\n", pfcount_in_2);
    return 0;
}

//定时器的回调函数
static void irq_test_timer_function(struct timer_list  *timer)
{
	
	printk("%d Number of page fault interrupts in 2 seconds: %ld\n",count,pfcount - pfcount_last);
	pfcount_in_2 = pfcount - pfcount_last;
	
	pfcount_last = pfcount;
	mod_timer(&test_timer, jiffies + 2 * HZ);
	count++;
}
 
static int my_proc_open(struct inode *inode, struct file *file)
{		
    /*4,在open函数中调用single_open绑定seq_show函数指针*/
    return single_open(file, my_proc_show, NULL);
}
 
/*2,填充proc_create函数中调用的flie_operations结构体
  其中my开头的函数为自己实现的函数，
  seq和single开头为内核实现好的函数，直接填充上就行
  open为必须填充函数
  */
static struct proc_ops my_fops = {
  .proc_open = my_proc_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};
 
static int __init my_init(void)
{


    struct proc_dir_entry *file;
    //创建父级目录，第二个参数NULL表示在/proc下
    //这里用我的学号当做文件名
    struct proc_dir_entry *parent = proc_mkdir("学号",NULL);

    /*1,
      首先要调用创建proc文件的函数，需要绑定flie_operations
      参数1：要创建的文件
      参数2：权限设置
      参数3：父级目录，如果传NULL，则在/proc下
      参数4：绑定flie_operations
      */
    file = proc_create("readpfcount", 0644, parent, &my_fops);
    if(!file)
        return -ENOMEM;
     
    //创建定时器  
    pfcount_last = pfcount;
	test_timer.expires  = jiffies + 2 * HZ;
	timer_setup(&test_timer, irq_test_timer_function, 0);
	
	add_timer(&test_timer);
	
	printk(KERN_INFO "already init and add timer\n");
    return 0;
}
 
/*6,删除proc文件*/
static void __exit my_exit(void)
{
  printk(KERN_INFO "exit timer drv\n");
  del_timer(&test_timer);
  //移除目录及文件
  remove_proc_entry("readpfcount", NULL);
}
 
module_init(my_init);
module_exit(my_exit);
6、编译安装后使用cat /proc/readpfcount即可

# 实验五-进行通信
代码如下：
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <semaphore.h>

#define SEAT 5    // 定义座位数

int queue[SEAT];
pthread_mutex_t mutex;   // 定义互斥信号量
sem_t full;       // 定义信号量，已就坐座位信号量
int count = 0;           // 记录阅览室人数

void *reader_activity(void *arg) {
    sem_wait(&full);  // p操作 加锁
    pthread_mutex_lock(&mutex);  //互斥锁上锁

    int i = count % SEAT;
    queue[i] = rand() % 1000000000 + 1;
    printf("----注册成功！----\n");
    printf("手机号码为:%d的读者进入阅览室\n", queue[i]);
    printf("正在读书中...\n");

    count++;
    pthread_mutex_unlock(&mutex);  //互斥锁解锁
    printf("此时阅览室已有人数为:%d\n", count);
    printf("---------------------------------\n");

        // 随机休眠一段时间
    int sleep_time = rand() % 10 + 3; // 休眠3到12秒之间的时间
    sleep(sleep_time);

    pthread_mutex_lock(&mutex);  //互斥锁上锁
    printf("手机号为%d的读者离开阅览室\n", queue[i]);
    queue[i] = 0;
    printf("----注销成功！----\n");

    count--;
    pthread_mutex_unlock(&mutex);
    sem_post(&full);  // v操作 解锁
    printf("此时阅览室已有人数为:%d\n", count);
    printf("---------------------------------\n");

}

int main(int argc, char *argv[]) {
    pthread_t tid;
    sem_init(&full, 0, SEAT);  // 初始化信号量

    int ret = pthread_mutex_init(&mutex, NULL); // 初始化线程
    if (ret != 0) {
        perror("mutex init error");  // 使用 perror 替换 fprintf
        exit(1);
    }

    while (1) {
        pthread_create(&tid, NULL, reader_activity, NULL);  // 创建线程
        pthread_detach(tid);  // 分离线程
        sleep(1);
    }

    sem_destroy(&full);  // 销毁信号量
    pthread_mutex_destroy(&mutex); // 销毁互斥锁
    return 0;
}
```
