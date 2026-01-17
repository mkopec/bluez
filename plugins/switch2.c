#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include <wordexp.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <linux/uhid.h>

#include <glib.h>
#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/log.h"
#include "src/service.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"

#define STORAGE_PATH "/var/lib/bluetooth/switch2_keys.ini"

#define NS2_BLE_SERVICE_UUID "ab7de9be-89fe-49ad-828f-118f09df7fd0"

#define NS2_FLAG_OK	BIT(0)
#define NS2_FLAG_NACK	BIT(2)

#define SPI_ADDR_LTK 0x1FA01A

enum switch2_cmd {
	NS2_CMD_FLASH = 0x02,
	NS2_CMD_INIT = 0x03,
	NS2_CMD_INIT_07 = 0x07, /* Sent during init sequence */
	NS2_CMD_BATTERY = 0x0b,
	NS2_CMD_FW_INFO = 0x10,
	NS2_CMD_BT_PAIR = 0x15,
	NS2_CMD_INIT_16 = 0x16, /* Sent during init sequence */
};

enum switch2_direction {
	NS2_DIR_IN = 0x00,
	NS2_DIR_OUT = 0x90,
};

enum switch2_transport {
	NS2_TRANS_USB = 0x00,
	NS2_TRANS_BT = 0x01,
};

enum switch2_ctlr_type {
	NS2_CTLR_TYPE_JCL = 0x00,
	NS2_CTLR_TYPE_JCR = 0x01,
	NS2_CTLR_TYPE_PRO = 0x02,
	NS2_CTLR_TYPE_GC = 0x03,
};

char * switch2_ctlr_type_name[] = {
	[NS2_CTLR_TYPE_JCL] = "Joy-Con (L)",
	[NS2_CTLR_TYPE_JCR] = "Joy-Con (R)",
	[NS2_CTLR_TYPE_PRO] = "Pro Controller",
	[NS2_CTLR_TYPE_GC] = "GameCube Controller",
};

struct switch2_cmd_header {
	uint8_t command;
	uint8_t direction;
	uint8_t transport;
	uint8_t subcommand;
	uint8_t unk1;
	uint8_t length;
	uint16_t unk2;
};

struct switch2_version_info {
	uint8_t major;
	uint8_t minor;
	uint8_t patch;
	uint8_t ctlr_type;
	uint32_t unk;
	int8_t dsp_major;
	int8_t dsp_minor;
	int8_t dsp_patch;
	int8_t dsp_type;
};

enum switch2_init_step {
	NS2_INIT_STARTING,
	NS2_INIT_CMD_07,
	NS2_INIT_CMD_16,
	NS2_INIT_FW_INFO,
	NS2_INIT_BT_CHECK_LTK,
	NS2_INIT_BT_ADDR_EXCHANGE,
	NS2_INIT_BT_LTK_COMPONENT_EXCHANGE,
	NS2_INIT_BT_LTK_CHALLENGE,
	NS2_INIT_BT_FINALIZE,
	NS2_INIT_ENABLE_HID,
	NS2_INIT_DONE,
};

enum switch2_report_id {
	NS2_REPORT_UNIFIED = 0x05,
	NS2_REPORT_JCL = 0x07,
	NS2_REPORT_JCR = 0x08,
	NS2_REPORT_PRO = 0x09,
	NS2_REPORT_GC = 0x0a,
	NS2_REPORT_CMD_TUNNEL = 0x40,
};

struct switch2_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_gatt_client *client;

	uint16_t handle_out;
	unsigned int notify_id_cmd;
	unsigned int notify_id_hid;
	unsigned int ready_id;

	enum switch2_init_step state;
	enum switch2_report_id report_id;
	const uint8_t *rdesc;
	ssize_t rdesc_size;
	const char *name;

	/* Pairing Data */
	uint8_t A1[16];   /* Host Public Key */
	uint8_t A2[16];   /* Host Challenge */
	uint8_t LTK[16];  /* Derived Long Term Key */

	/* uHID */
	int uhid_fd;
	GIOChannel *uhid_io;
	unsigned int uhid_watch_id;
};

static const uint8_t rdesc_pro[] = {
	0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
	0x09, 0x05,        // Usage (Game Pad)
	0xA1, 0x01,        // Collection (Application)
	0x85, 0x05,        //   Report ID (5)
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x01,        //   Usage (0x01)
	0x15, 0x00,        //   Logical Minimum (0)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x3F,        //   Report Count (63)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x85, 0x09,        //   Report ID (9)
	0x09, 0x01,        //   Usage (0x01)
	0x95, 0x02,        //   Report Count (2)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0x09,        //   Usage Page (Button)
	0x19, 0x01,        //   Usage Minimum (0x01)
	0x29, 0x15,        //   Usage Maximum (0x15)
	0x25, 0x01,        //   Logical Maximum (1)
	0x95, 0x15,        //   Report Count (21)
	0x75, 0x01,        //   Report Size (1)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x95, 0x01,        //   Report Count (1)
	0x75, 0x03,        //   Report Size (3)
	0x81, 0x03,        //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0x01,        //   Usage Page (Generic Desktop Ctrls)
	0x09, 0x01,        //   Usage (Pointer)
	0xA1, 0x00,        //   Collection (Physical)
	0x09, 0x30,        //     Usage (X)
	0x09, 0x31,        //     Usage (Y)
	0x09, 0x33,        //     Usage (Rx)
	0x09, 0x35,        //     Usage (Rz)
	0x26, 0xFF, 0x0F,  //     Logical Maximum (4095)
	0x95, 0x04,        //     Report Count (4)
	0x75, 0x0C,        //     Report Size (12)
	0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0xC0,              //   End Collection
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x02,        //   Usage (0x02)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x34,        //   Report Count (52)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x85, 0x02,        //   Report ID (2)
	0x09, 0x01,        //   Usage (0x01)
	0x95, 0x3F,        //   Report Count (63)
	0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
	0xC0,              // End Collection
	0x06, 0x00, 0xFF,  // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        // Usage (Vendor Usage 1)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x40,        //   Report ID (0x40 - NS2_REPORT_CMD_TUNNEL)
    0x09, 0x02,        //   Usage (Vendor Usage 2)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x95, 0x40,        //   Report Count (64 bytes)
    0x75, 0x08,        //   Report Size (8 bits)
    0x81, 0x02,        //   Input (Data,Var,Abs)
    0x91, 0x02,        //   Output (Data,Var,Abs)
    0xC0,              // End Collection
};

static const uint8_t rdesc_jcr[] = {
	0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
	0x09, 0x05,        // Usage (Game Pad)
	0xA1, 0x01,        // Collection (Application)
	0x85, 0x05,        //   Report ID (5)
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x01,        //   Usage (0x01)
	0x15, 0x00,        //   Logical Minimum (0)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x3F,        //   Report Count (63)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x85, 0x08,        //   Report ID (8)
	0x09, 0x01,        //   Usage (0x01)
	0x95, 0x02,        //   Report Count (2)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0x09,        //   Usage Page (Button)
	0x19, 0x01,        //   Usage Minimum (0x01)
	0x29, 0x10,        //   Usage Maximum (0x10)
	0x25, 0x01,        //   Logical Maximum (1)
	0x95, 0x10,        //   Report Count (16)
	0x75, 0x01,        //   Report Size (1)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x01,        //   Usage (0x01)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x01,        //   Report Count (1)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0x01,        //   Usage Page (Generic Desktop Ctrls)
	0x09, 0x01,        //   Usage (Pointer)
	0xA1, 0x00,        //   Collection (Physical)
	0x09, 0x30,        //     Usage (X)
	0x09, 0x31,        //     Usage (Y)
	0x26, 0xFF, 0x0F,  //     Logical Maximum (4095)
	0x95, 0x02,        //     Report Count (2)
	0x75, 0x0C,        //     Report Size (12)
	0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0xC0,              //   End Collection
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x02,        //   Usage (0x02)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x37,        //   Report Count (55)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x85, 0x01,        //   Report ID (1)
	0x09, 0x01,        //   Usage (0x01)
	0x95, 0x3F,        //   Report Count (63)
	0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
	0xC0,              // End Collection
	0x06, 0x00, 0xFF,  // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        // Usage (Vendor Usage 1)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x40,        //   Report ID (0x40 - NS2_REPORT_CMD_TUNNEL)
    0x09, 0x02,        //   Usage (Vendor Usage 2)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x95, 0x40,        //   Report Count (64 bytes)
    0x75, 0x08,        //   Report Size (8 bits)
    0x81, 0x02,        //   Input (Data,Var,Abs)
    0x91, 0x02,        //   Output (Data,Var,Abs)
    0xC0,              // End Collection
};

static const uint8_t rdesc_jcl[] = {
	0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
	0x09, 0x05,        // Usage (Game Pad)
	0xA1, 0x01,        // Collection (Application)
	0x85, 0x05,        //   Report ID (5)
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x01,        //   Usage (0x01)
	0x15, 0x00,        //   Logical Minimum (0)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x3F,        //   Report Count (63)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x85, 0x07,        //   Report ID (7)
	0x09, 0x01,        //   Usage (0x01)
	0x95, 0x02,        //   Report Count (2)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0x09,        //   Usage Page (Button)
	0x19, 0x01,        //   Usage Minimum (0x01)
	0x29, 0x10,        //   Usage Maximum (0x10)
	0x25, 0x01,        //   Logical Maximum (1)
	0x95, 0x10,        //   Report Count (16)
	0x75, 0x01,        //   Report Size (1)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x01,        //   Usage (0x01)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x01,        //   Report Count (1)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x05, 0x01,        //   Usage Page (Generic Desktop Ctrls)
	0x09, 0x01,        //   Usage (Pointer)
	0xA1, 0x00,        //   Collection (Physical)
	0x09, 0x30,        //     Usage (X)
	0x09, 0x31,        //     Usage (Y)
	0x26, 0xFF, 0x0F,  //     Logical Maximum (4095)
	0x95, 0x02,        //     Report Count (2)
	0x75, 0x0C,        //     Report Size (12)
	0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0xC0,              //   End Collection
	0x05, 0xFF,        //   Usage Page (Reserved 0xFF)
	0x09, 0x02,        //   Usage (0x02)
	0x26, 0xFF, 0x00,  //   Logical Maximum (255)
	0x95, 0x37,        //   Report Count (55)
	0x75, 0x08,        //   Report Size (8)
	0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
	0x85, 0x01,        //   Report ID (1)
	0x09, 0x01,        //   Usage (0x01)
	0x95, 0x3F,        //   Report Count (63)
	0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
	0xC0,              // End Collection
	0x06, 0x00, 0xFF,  // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        // Usage (Vendor Usage 1)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x40,        //   Report ID (0x40 - NS2_REPORT_CMD_TUNNEL)
    0x09, 0x02,        //   Usage (Vendor Usage 2)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x95, 0x40,        //   Report Count (64 bytes)
    0x75, 0x08,        //   Report Size (8 bits)
    0x81, 0x02,        //   Input (Data,Var,Abs)
    0x91, 0x02,        //   Output (Data,Var,Abs)
    0xC0,              // End Collection
};

static void write_uhid_padded(struct switch2_data *data, uint8_t report_id, const uint8_t *payload, uint16_t length)
{
    if (data->uhid_fd <= 0)
        return;

    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;

    ev.u.input2.size = 65;
    ev.u.input2.data[0] = report_id;

    size_t to_copy = (length > 64) ? 64 : length;
    if (payload && to_copy > 0)
        memcpy(&ev.u.input2.data[1], payload, to_copy);

    write(data->uhid_fd, &ev, sizeof(ev));
}

static void send_cmd(struct switch2_data *data, uint8_t command, uint8_t subcommand, const uint8_t *payload, size_t payload_len) {
	uint8_t buf[256];
	memset(buf, 0, sizeof(buf));

	struct switch2_cmd_header *hdr = (struct switch2_cmd_header *)buf;
	hdr->command = command;
	hdr->direction = NS2_DIR_OUT | NS2_FLAG_OK;
	hdr->transport = NS2_TRANS_BT;
	hdr->subcommand = subcommand;
	hdr->unk1 = 0x00;
	hdr->length = (uint8_t)payload_len;
	hdr->unk2 = 0x0000;

	if (payload && payload_len > 0)
		memcpy(buf + sizeof(struct switch2_cmd_header), payload, payload_len);

	info("Switch2: OUT 0x%02X [Sub %02X] (Total %zu)", command, subcommand,
			payload_len + sizeof(struct switch2_cmd_header));

	if (data->handle_out && data->client)
		bt_gatt_client_write_without_response(data->client, data->handle_out,
				false, buf, payload_len + sizeof(struct switch2_cmd_header));
}

static gboolean uhid_read_handler(GIOChannel *source, GIOCondition condition, gpointer user_data) {
	struct switch2_data *data = user_data;
	struct uhid_event ev;
	ssize_t ret;

	if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		return FALSE;

	ret = read(data->uhid_fd, &ev, sizeof(ev));
	if (ret < (ssize_t)sizeof(ev.type))
		return TRUE;

	switch (ev.type) {
	case UHID_START:
	case UHID_OPEN:
		// Kernel driver attached/opened
		info("Kernel driver attached");
		break;

	case UHID_OUTPUT:
		info("Switch2: UHID IN 0x%02x (Size = %d)", ev.u.output.data[1], ev.u.output.size);
		if (ev.u.output.rtype == UHID_OUTPUT_REPORT) {
			uint8_t report_id = ev.u.output.data[0];

			if (report_id == NS2_REPORT_CMD_TUNNEL) {
				/* Configuration data - Encapsulated in HID reports with ID 0x40 */
				struct switch2_cmd_header *hdr = (struct switch2_cmd_header *)&ev.u.output.data[1];

				size_t header_size = sizeof(struct switch2_cmd_header);
				size_t overhead = 1 + header_size;

				if (ev.u.output.size >= overhead) {
					uint8_t *payload = &ev.u.output.data[overhead];
					size_t payload_len = ev.u.output.size - overhead;

					send_cmd(data, hdr->command, hdr->subcommand, payload, payload_len);
				}
			} else {
				/* Rumble - Handle 0x0012 */
				if (data->client && data->handle_out && ev.u.output.size > 1) {
					bt_gatt_client_write_without_response(data->client, 0x0012,
														  false, &ev.u.output.data[1], ev.u.output.size - 1);
				}
			}
		}
		break;

	default:
		break;
	}

	return TRUE;
}

static int create_uhid_device(struct switch2_data *data) {
	struct uhid_event ev;
	const bdaddr_t *src, *dst;
	char src_str[18], dst_str[18];

	if (data->uhid_fd > 0) return 0;

	data->uhid_fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
	if (data->uhid_fd < 0) return -errno;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE2;
	strncpy((char *)ev.u.create2.name, data->name, sizeof(ev.u.create2.name) - 1);
	ev.u.create2.vendor = 0x057e;
	ev.u.create2.product = 0x2069;
	ev.u.create2.version = 0x0001;
	ev.u.create2.bus = BUS_BLUETOOTH;

	ev.u.create2.rd_size = data->rdesc_size;
	memcpy(ev.u.create2.rd_data, data->rdesc, data->rdesc_size);

	src = btd_adapter_get_address(device_get_adapter(data->device));
	dst = device_get_address(data->device);
	ba2str(src, src_str);
	ba2str(dst, dst_str);
	strncpy((char *)ev.u.create2.phys, src_str, sizeof(ev.u.create2.phys) - 1);
	strncpy((char *)ev.u.create2.uniq, dst_str, sizeof(ev.u.create2.uniq) - 1);

	if (write(data->uhid_fd, &ev, sizeof(ev)) < 0) {
		int err = -errno;
		close(data->uhid_fd);
		data->uhid_fd = -1;
		return err;
    }

	data->uhid_io = g_io_channel_unix_new(data->uhid_fd);
	g_io_channel_set_encoding(data->uhid_io, NULL, NULL);
	data->uhid_watch_id = g_io_add_watch(data->uhid_io,
										G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
										uhid_read_handler, data);

	info("Switch2: Created uHID device");

	return 0;
}

static void cleanup_uhid(struct switch2_data *data) {
	if (data->uhid_watch_id) {
		g_source_remove(data->uhid_watch_id);
		data->uhid_watch_id = 0;
	}

	if (data->uhid_io) {
		g_io_channel_unref(data->uhid_io);
		data->uhid_io = NULL;
	}

	if (data->uhid_fd > 0) {
		struct uhid_event ev;
		memset(&ev, 0, sizeof(ev));
		ev.type = UHID_DESTROY;
		write(data->uhid_fd, &ev, sizeof(ev));

		close(data->uhid_fd);
		data->uhid_fd = -1;
	}
}

static void save_ltk(struct switch2_data *data) {
	GKeyFile *key_file = g_key_file_new();
	char addr[18];

	// Load existing file to preserve other devices
	g_key_file_load_from_file(key_file, STORAGE_PATH, G_KEY_FILE_NONE, NULL);

	ba2str(device_get_address(data->device), addr);

	// Convert LTK bytes to hex string
	char ltk_str[33];
	for(int i=0; i<16; i++) sprintf(&ltk_str[i*2], "%02X", data->LTK[i]);
	ltk_str[32] = '\0';

	g_key_file_set_string(key_file, "ltk", addr, ltk_str);

	// Save to disk
	gsize length = 0;
	gchar *content = g_key_file_to_data(key_file, &length, NULL);
	g_file_set_contents(STORAGE_PATH, content, length, NULL);

	g_free(content);
	g_key_file_free(key_file);
	info("Switch2: Persisted LTK for %s", addr);
}

static bool load_ltk(struct switch2_data *data) {
	GKeyFile *key_file = g_key_file_new();
	char addr[18];
	GError *error = NULL;
	bool success = false;

	if (!g_key_file_load_from_file(key_file, STORAGE_PATH, G_KEY_FILE_NONE, NULL)) {
		g_key_file_free(key_file);
		return false;
	}

	ba2str(device_get_address(data->device), addr);
	gchar *ltk_str = g_key_file_get_string(key_file, "ltk", addr, &error);

	if (ltk_str && strlen(ltk_str) == 32) {
		// Convert hex string back to bytes
		for(int i=0; i<16; i++) {
			unsigned int byte;
			sscanf(&ltk_str[i*2], "%02X", &byte);
			data->LTK[i] = (uint8_t)byte;
		}
		success = true;
		info("Switch2: Loaded existing LTK for %s", addr);
	}

	if (ltk_str) g_free(ltk_str);
	g_key_file_free(key_file);
	return success;
}

static void send_read_spi(struct switch2_data *data, uint32_t address, uint8_t length) {
    uint8_t payload[8] = { length, 0x7e };

    payload[4] = (address & 0xFF);
    payload[5] = ((address >> 8) & 0xFF);
    payload[6] = ((address >> 16) & 0xFF);
    payload[7] = 0x00;

    send_cmd(data, NS2_CMD_FLASH, 0x04, payload, 8);
}

static void parse_fw_info(struct switch2_data *data, const uint8_t *raw) {
	struct switch2_version_info *fw_info = (struct switch2_version_info *)raw;

	info("Switch2: FW version: %02d.%02d.%02d", fw_info->major, fw_info->minor, fw_info->patch);

	if (fw_info->ctlr_type > NS2_CTLR_TYPE_GC) {
		info("Switch2: Type unrecognized!");
	} else {
		data->name = switch2_ctlr_type_name[fw_info->ctlr_type];
		info("Switch2: Type: %s", data->name);
	}


	if (fw_info->ctlr_type == NS2_CTLR_TYPE_PRO)
		info("Switch2: DSP: %02d.%02d.%02d.%02d", fw_info->dsp_major, fw_info->dsp_minor, fw_info->dsp_patch, fw_info->dsp_type);

	switch (fw_info->ctlr_type) {
	case NS2_CTLR_TYPE_JCL:
		data->report_id = NS2_REPORT_JCL;
		data->rdesc = rdesc_jcl;
		data->rdesc_size = sizeof(rdesc_jcl);
		break;
	case NS2_CTLR_TYPE_JCR:
		data->report_id = NS2_REPORT_JCR;
		data->rdesc = rdesc_jcr;
		data->rdesc_size = sizeof(rdesc_jcr);
		break;
	case NS2_CTLR_TYPE_PRO:
		data->report_id = NS2_REPORT_PRO;
		data->rdesc = rdesc_pro;
		data->rdesc_size = sizeof(rdesc_pro);
		break;
	case NS2_CTLR_TYPE_GC:
		data->report_id = NS2_REPORT_GC;
		break;
	default:
		data->report_id = NS2_REPORT_PRO;
		data->rdesc = rdesc_pro;
		data->rdesc_size = sizeof(rdesc_pro);
		break;
	}
}

static void pairing_exchange_addr(struct switch2_data *data) {
	struct btd_adapter *adapter = device_get_adapter(data->device);
	const bdaddr_t *addr = btd_adapter_get_address(adapter);
	uint8_t payload[14];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00; /* Unknown, always 0x00 */
	payload[1] = 0x02; /* Number of host BT addresses */
	memcpy(&payload[2], addr, 6);
	memcpy(&payload[8], addr, 6);

	send_cmd(data, NS2_CMD_BT_PAIR, 0x01, payload, sizeof(payload));
}

static void pairing_exchange_ltk_components(struct switch2_data *data) {
	uint8_t payload[17];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00; /* Unknown, always 0x00 */

	/* Generate A1 */
	for (int i = 0; i < 16; i++)
		data->A1[i] = rand() & 0xFF;

	memcpy(&payload[1], data->A1, 16);

	send_cmd(data, NS2_CMD_BT_PAIR, 0x04, payload, sizeof(payload));
}

static void pairing_send_challenge(struct switch2_data *data) {
	uint8_t payload[17];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00; /* Unknown, always 0x00 */

	/* Generate A2 */
	for (int i = 0; i < 16; i++)
		data->A2[i] = rand() & 0xFF;

	memcpy(&payload[1], data->A2, 16);

	send_cmd(data, NS2_CMD_BT_PAIR, 0x02, payload, sizeof(payload));
}

static void pairing_finalize(struct switch2_data *data) {
	uint8_t payload = 0;
	send_cmd(data, NS2_CMD_BT_PAIR, 0x03, &payload, sizeof(payload));
	btd_device_set_trusted(data->device, true);
	btd_device_set_temporary(data->device, false);
}

static void enable_hid_reports(struct switch2_data *data) {
	uint8_t cmd[2] = {0x01, 0x00};
	bt_gatt_client_write_value(data->client, 0x000f, cmd, 2, NULL, NULL, NULL);
}

static void resp_notify_handler(uint16_t value_handle, const uint8_t *value, uint16_t length, void *user_data) {
	struct switch2_data *data = user_data;
	struct switch2_cmd_header *hdr = (struct switch2_cmd_header *)value;
	const uint8_t *payload = value + sizeof(struct switch2_cmd_header);

	info("Switch2: IN 0x%02x (size: %d)", hdr->command, length);

	switch (data->state) {
	case NS2_INIT_CMD_07:
		if (hdr->command == NS2_CMD_INIT_07) {
			data->state = NS2_INIT_CMD_16;
			send_cmd(data, NS2_CMD_INIT_16, 0x01, NULL, 0);
		}
		break;
	case NS2_INIT_CMD_16:
		if (hdr->command == NS2_CMD_INIT_16) {
			data->state = NS2_INIT_FW_INFO;
			send_cmd(data, NS2_CMD_FW_INFO, 0x01, NULL, 0);
		}
		break;
	case NS2_INIT_FW_INFO:
		if (hdr->command == NS2_CMD_FW_INFO) {
			parse_fw_info(data, payload);
			data->state = NS2_INIT_BT_CHECK_LTK;
			send_read_spi(data, SPI_ADDR_LTK, 16);
		}
	case NS2_INIT_BT_CHECK_LTK:
		if (hdr->command == NS2_CMD_FLASH) {
			if (memcmp(data->LTK, &payload[8], 16) == 0) {
				info("Switch2: LTK Match! Skipping pairing.");
				data->state = NS2_INIT_DONE;
				enable_hid_reports(data);
				create_uhid_device(data);
			} else {
				info("Switch2: LTK Mismatch or New Device. Starting pairing...");
				data->state = NS2_INIT_BT_ADDR_EXCHANGE;
				pairing_exchange_addr(data);
			}
		}

	case NS2_INIT_BT_ADDR_EXCHANGE:
		if (hdr->command == NS2_CMD_BT_PAIR && hdr->subcommand == 0x01) {
			data->state = NS2_INIT_BT_LTK_COMPONENT_EXCHANGE;
			pairing_exchange_ltk_components(data);
		}
		break;
	case NS2_INIT_BT_LTK_COMPONENT_EXCHANGE:
		if (hdr->command == NS2_CMD_BT_PAIR && hdr->subcommand == 0x04) {
			data->state = NS2_INIT_BT_FINALIZE;

			for (int i = 0; i < 16; ++i)
				data->LTK[i] = data->A1[i] ^ payload[i + 1];

			pairing_send_challenge(data);
		}
		break;
	case NS2_INIT_BT_FINALIZE:
		if (hdr->command == NS2_CMD_BT_PAIR && hdr->subcommand == 0x02) {
			data->state = NS2_INIT_ENABLE_HID;
			/* TODO: Verify B2 response */
			pairing_finalize(data);
			save_ltk(data);
		}
		break;
	case NS2_INIT_ENABLE_HID:
		if (hdr->command == NS2_CMD_BT_PAIR && hdr->subcommand == 0x03) {
			data->state = NS2_INIT_DONE;
			enable_hid_reports(data);
			create_uhid_device(data);
		}
		break;
	case NS2_INIT_DONE:
		/* Forward command responses to uHID */
		info("Switch2: Forwarding command response to uHID");
		info("Switch2: UHID OUT 0x%02x (size: %d)", value[0], length);

		write_uhid_padded(data, NS2_REPORT_CMD_TUNNEL, value, length);
		break;
	default:
		break;
	}
}

static void hid_notify_handler(uint16_t value_handle, const uint8_t *value, uint16_t length, void *user_data) {
	struct switch2_data *data = user_data;

	if (data->uhid_fd > 0)
		write_uhid_padded(data, data->report_id, value, length);
}

static void notify_registered_cb(uint16_t att_ecode, void *user_data) {
	struct switch2_data *data = user_data;

	if (att_ecode) {
		error("Switch2: Failed to register notify: 0x%04x", att_ecode);
		return;
	}

	uint8_t init_cmd[2] = {0x01, 0x00};
	/* Sent by Switch 2 console as the first command during init sequence */
	bt_gatt_client_write_value(data->client, 0x0005, init_cmd, 2, NULL, NULL, NULL);
	/* Enable notifications for command responses on handle 0x001E */
	bt_gatt_client_write_value(data->client, 0x001B, init_cmd, 2, NULL, NULL, NULL);

    data->state = NS2_INIT_CMD_07;
    send_cmd(data, NS2_CMD_INIT_07, 0x01, NULL, 0);
}

static void setup_gatt(struct switch2_data *data) {
	data->handle_out = 0x0014;

	data->notify_id_cmd = bt_gatt_client_register_notify(data->client, 0x001A, notify_registered_cb, resp_notify_handler, data, NULL);
	data->notify_id_hid = bt_gatt_client_register_notify(data->client, 0x000E, NULL, hid_notify_handler, data, NULL);
}

static void gatt_ready_cb(bool success, uint8_t att_ecode, void *user_data) {
	struct switch2_data *data = user_data;

	if (success)
		setup_gatt(data);
}

static int switch2_probe(struct btd_service *service) {
	struct btd_device *device = btd_service_get_device(service);
	struct switch2_data *data = g_try_new0(struct switch2_data, 1);

	data->device = btd_device_ref(device);
	data->service = btd_service_ref(service);
	data->state = NS2_INIT_CMD_07;
	btd_service_set_user_data(service, data);

	srand(time(NULL));

	return 0;
}

static void switch2_remove(struct btd_service *service) {
	struct switch2_data *data = btd_service_get_user_data(service);
	if (!data)
		return;

	if (data->client && data->notify_id_cmd)
		bt_gatt_client_unregister_notify(data->client, data->notify_id_cmd);
	if (data->client && data->notify_id_hid)
		bt_gatt_client_unregister_notify(data->client, data->notify_id_hid);

	if (data->client && data->ready_id)
		bt_gatt_client_ready_unregister(data->client, data->ready_id);

	btd_device_unref(data->device);
	btd_service_unref(data->service);
	g_free(data);
}

static int switch2_connect(struct btd_service *service) {
	struct switch2_data *data = btd_service_get_user_data(service);

	data->client = btd_device_get_gatt_client(data->device);
	if (!data->client)
		return -ENOTCONN;

	if (bt_gatt_client_is_ready(data->client))
		setup_gatt(data);
	else
		data->ready_id = bt_gatt_client_ready_register(data->client, gatt_ready_cb, data, NULL);

	load_ltk(data);

	btd_service_connecting_complete(service, 0);
	return 0;
}

static int switch2_disconnect(struct btd_service *service) {
	struct switch2_data *data = btd_service_get_user_data(service);

	btd_service_disconnecting_complete(service, 0);
	cleanup_uhid(data);

	return 0;
}

static struct btd_profile switch2_profile = {
	.name = "switch2-le",
	.remote_uuid = NS2_BLE_SERVICE_UUID,
	.device_probe = switch2_probe,
	.device_remove = switch2_remove,
	.connect = switch2_connect,
	.disconnect = switch2_disconnect,
	.accept = switch2_connect,
	.auto_connect = true,
};

static int switch2_init(void) {
	btd_profile_register(&switch2_profile);
	return 0;
}

static void switch2_exit(void) {
	btd_profile_unregister(&switch2_profile);
}

BLUETOOTH_PLUGIN_DEFINE(switch2, VERSION, BLUETOOTH_PLUGIN_PRIORITY_LOW, switch2_init, switch2_exit)
