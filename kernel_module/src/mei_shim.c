// SPDX-License-Identifier: GPL-2.0-only
//
// mei_shim.c — C glue between the Rust mei_driver module and the Linux
// MEI (Management Engine Interface) bus subsystem.
//
// The MEI bus API (struct mei_cl_driver, mei_cl_driver_register, etc.)
// is not yet wrapped in Rust bindings in the mainline rust/kernel/ tree.
// This thin C file:
//   1. Defines the static struct mei_cl_driver with sysentinel's MKHI UUID.
//   2. Calls back into sysentinel_mei_probe / sysentinel_mei_remove, which
//      are exported as no_mangle extern "C" functions from mei_driver.rs.
//   3. Exposes sysentinel_mei_register / _unregister / _send / _recv to the
//      Rust side via the extern "C" declarations in mei_driver.rs.
//
// Compile with:
//   make MEI=y KDIR=/path/to/kernel/source
//
// Requires CONFIG_INTEL_MEI=y in the target kernel.

#include <linux/module.h>
#include <linux/mei_cl_bus.h>
#include <linux/uuid.h>

MODULE_LICENSE("GPL");

/* Forward declarations of Rust callbacks exported from mei_driver.rs. */
extern int  sysentinel_mei_probe(struct mei_cl_device *cldev);
extern void sysentinel_mei_remove(struct mei_cl_device *cldev);

/* ── MKHI MEI client UUID ───────────────────────────────────────────────────
 *
 * {8e6a6715-9abc-4043-88ef-9e39c6f63e0f}
 *
 * This is the standard MKHI (ME Kernel Host Interface) client that handles
 * firmware-version and general ME management commands.
 */
static const uuid_le sysentinel_mei_mkhi_guid =
    UUID_LE(0x8e6a6715, 0x9abc, 0x4043,
            0x88, 0xef, 0x9e, 0x39, 0xc6, 0xf6, 0x3e, 0x0f);

static struct mei_cl_device_id sysentinel_mei_id_table[] = {
    { .uuid = { /* same as above */ }, .version = MEI_CL_VERSION_ANY },
    { }
};

/*
 * We have to fill the uuid in the id_table separately because designated
 * initialisers for uuid_le are messy to write portably in C89/C99.
 */
static void __init fill_id_table(void)
{
    memcpy(&sysentinel_mei_id_table[0].uuid,
           &sysentinel_mei_mkhi_guid,
           sizeof(uuid_le));
}

/* ── mei_cl_driver struct ────────────────────────────────────────────────── */

static int shim_probe(struct mei_cl_device *cldev,
                      const struct mei_cl_device_id *id)
{
    int ret;
    /*
     * Enable the device before calling into Rust; this tells the MEI bus
     * to start receiving messages for this client.
     *
     * mei_cldev_enable() was introduced in kernel 4.10 to replace the older
     * mei_cl_enable_device(). Adjust the call if your kernel is older.
     */
    ret = mei_cldev_enable(cldev);
    if (ret < 0)
        return ret;

    ret = sysentinel_mei_probe(cldev);
    if (ret < 0)
        mei_cldev_disable(cldev);

    return ret;
}

static void shim_remove(struct mei_cl_device *cldev)
{
    sysentinel_mei_remove(cldev);
    mei_cldev_disable(cldev);
}

static struct mei_cl_driver sysentinel_mei_driver = {
    .id_table = sysentinel_mei_id_table,
    .name     = "sysentinel",
    .probe    = shim_probe,
    .remove   = shim_remove,
};

/* ── Public functions called from Rust ──────────────────────────────────── */

int sysentinel_mei_register(void)
{
    fill_id_table();
    return mei_cldev_driver_register(&sysentinel_mei_driver);
}

void sysentinel_mei_unregister(void)
{
    mei_cldev_driver_unregister(&sysentinel_mei_driver);
}

/*
 * sysentinel_mei_send / _recv — thin wrappers around the mei_cldev_send /
 * mei_cldev_recv API (kernel ≥ 4.11). For older kernels, replace with
 * mei_cl_send() / mei_cl_recv() from the older internal API.
 */
ssize_t sysentinel_mei_send(struct mei_cl_device *cldev,
                             const u8 *buf, size_t len)
{
    return mei_cldev_send(cldev, (u8 *)buf, len);
}
EXPORT_SYMBOL_GPL(sysentinel_mei_send);

ssize_t sysentinel_mei_recv(struct mei_cl_device *cldev,
                             u8 *buf, size_t len)
{
    return mei_cldev_recv(cldev, buf, len);
}
EXPORT_SYMBOL_GPL(sysentinel_mei_recv);
