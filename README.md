# KUMSAN: Detecting Uninitialized Memory Usage for the Linux Kernel

KUMSAN is a kernel uninitialized memory usage detection tool. It is based on compiler piling, inserts detection code before memory access of uninitialized kernel heap space and stack space, and uses shadow memory to monitor whether the value of the corresponding memory location is overwritten, and detects memory usage that achieves a single byte accuracy. We implemented KUMSAN on the latest Linux x86-64 kernel and Android AArch64 kernel.

## Patch
Clone the Linux kernel and apply the patch. The patch is based on linux-5.2-rc4. So download https://git.kernel.org/torvalds/t/linux-5.2-rc4.tar.gz and extract it to linux-5.2-rc4 and do:

```
cd linux-5.2-rc4
git apply /path/to/patch
cp /path/to/example.config .config
```

Make sure the CONFIG_KASAN is enabled and compile it. For example

```
grep KASAN example.config # 
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=1
CONFIG_TEST_KASAN=m
```

## Testing
You can just modify some kernel code and add some uninitialized memory using codes to test it. Another way to test the kernel is to use the test module. Make sure the  CONFIG_TEST_KASAN=m is set and the lib/test_kasan.ko is generated. Boot the kernel and load the module.

## Example of report
The p9_tag_alloc() does not initialize the transport error t_err field.
The struct p9_req_t *req is allocated and stored in a struct p9_client
variable. 
```
==================================================================
BUG: KASAN: unknown-crash in p9_conn_cancel+0x2d9/0x3b0 net/9p/trans_fd.c:211
Read of size 4 at addr ffff88806881200c by task kworker/0:3/1534

CPU: 0 PID: 1534 Comm: kworker/0:3 Not tainted 5.2.0-rc4+ #70
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
Workqueue: events p9_write_work
Call Trace:
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x75/0xae lib/dump_stack.c:113
 print_address_description mm/kasan/report.c:188 [inline]
 __kasan_report+0x17c/0x3e6 mm/kasan/report.c:326
 kasan_report+0xe/0x20 mm/kasan/common.c:650
 p9_conn_cancel+0x2d9/0x3b0 net/9p/trans_fd.c:211
 p9_write_work+0x183/0x4a0 net/9p/trans_fd.c:514
 process_one_work+0x4d1/0x8c0 kernel/workqueue.c:2269
 worker_thread+0x6e/0x780 kernel/workqueue.c:2415
 kthread+0x1ca/0x1f0 kernel/kthread.c:255
 ret_from_fork+0x35/0x40 arch/x86/entry/entry_64.S:352

Allocated by task 2064:
 save_stack+0x19/0x80 mm/kasan/common.c:71
 set_track mm/kasan/common.c:79 [inline]
 __kasan_kmalloc.constprop.3+0xbc/0x120 mm/kasan/common.c:525
 slab_post_alloc_hook mm/slab.h:437 [inline]
 slab_alloc_node mm/slub.c:2748 [inline]
 slab_alloc mm/slub.c:2756 [inline]
 kmem_cache_alloc+0xa7/0x170 mm/slub.c:2761
 p9_tag_alloc net/9p/client.c:270 [inline]
 p9_client_prepare_req.part.9+0x3b/0x380 net/9p/client.c:698
 p9_client_prepare_req net/9p/client.c:735 [inline]
 p9_client_rpc+0x15e/0x880 net/9p/client.c:735
 p9_client_version net/9p/client.c:952 [inline]
 p9_client_create+0x3d0/0xac0 net/9p/client.c:1052
 v9fs_session_init+0x192/0xc80 fs/9p/v9fs.c:406
 v9fs_mount+0x67/0x470 fs/9p/vfs_super.c:120
 legacy_get_tree+0x70/0xd0 fs/fs_context.c:661
 vfs_get_tree+0x4a/0x1c0 fs/super.c:1476
 do_new_mount fs/namespace.c:2790 [inline]
 do_mount+0xba9/0xf90 fs/namespace.c:3110
 ksys_mount+0xa8/0x120 fs/namespace.c:3319
 __do_sys_mount fs/namespace.c:3333 [inline]
 __se_sys_mount fs/namespace.c:3330 [inline]
 __x64_sys_mount+0x62/0x70 fs/namespace.c:3330
 do_syscall_64+0x7e/0x1f0 arch/x86/entry/common.c:302
 entry_SYSCALL_64_after_hwframe+0x44/0xa9

Freed by task 0:
(stack is not available)

The buggy address belongs to the object at ffff888068812008
 which belongs to the cache p9_req_t of size 144
The buggy address is located 4 bytes inside of
 144-byte region [ffff888068812008, ffff888068812098)
The buggy address belongs to the page:
page:ffffea0001a20480 refcount:1 mapcount:0 mapping:ffff888068bbb740 index:0xffff888068813d90 compound_mapcount: 0
flags: 0x100000000010200(slab|head)
raw: 0100000000010200 ffff888068aa2450 ffff888068aa2450 ffff888068bbb740
raw: ffff888068813d90 0000000000100001 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff888068811fe0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
 ffff888068811ff0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
>ffff888068812000: cc cc cc cc cc cc cc cc 02 00 00 00 bb bb bb bb
                                                       ^
 ffff888068812010: 03 00 00 00 bb bb bb bb 00 00 00 00 bb bb bb bb
 ffff888068812020: 58 f8 ff 68 80 88 ff ff 58 f8 ff 68 80 88 ff ff

Memory state around the buggy address:
 ffff888068811f00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 ffff888068811f80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
>ffff888068812000: fc 0f 0f 0f 00 00 04 00 00 00 00 0f 00 00 00 00
                      ^
 ffff888068812080: ff 00 00 fc fc fc 00 00 00 00 00 00 00 00 00 00
 ffff888068812100: 00 00 00 00 fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================
```
# Trophies 
[PATCH] ipc/msg.c: consolidate all xxxctl_down() functions

https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?h=next-20191010&id=7afbb1970dd96ecc7083385cb77c701c81ba870b

[PATCH] 9p: Transport error uninitialized

https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/diff/queue-5.3/9p-transport-error-uninitialized.patch?id=c70c160a43a1e695533b86ba35e8f612352b60f3

https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/diff/queue-4.19/9p-transport-error-uninitialized.patch?id=d65b160f6fc8669b1f91f6a737d503b58340c066
