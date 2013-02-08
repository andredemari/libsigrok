/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2013 Tom Schutter <t.schutter@comcast.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include "libsigrok.h"
#include "libsigrok-internal.h"
#include "protocol.h"

#define POLABS_POSCOPE_MEGA1_VENDOR "PoLabs"

/* USB endpoint for commands */
#define EP_COMMAND_OUT (0x01 | LIBUSB_ENDPOINT_OUT)

/* USB endpoint for returned data */
#define EP_DATA_RETURN (0x02 | LIBUSB_ENDPOINT_IN)

/* USB endpoint for command return value */
#define EP_COMMAND_RET (0x03 | LIBUSB_ENDPOINT_IN)

#define CMD_OSC_DIV		0x01
#define CMD_OSC_FREQ	0x02
#define CMD_OSC_TRG		0x03
#define CMD_OSC_ONOFF	0x04
#define CMD_OSC_RUN		0x05
#define CMD_OSC_STOP	0x06
#define CMD_OSC_ACDC	0x07
#define CMD_LOG_PCFG	0x22
#define CMD_LOG_STOP	0x26
#define CMD_FRM_VER		0x5e
#define CMD_RESET		0xff

SR_PRIV const uint64_t polabs_poscope_mega1_samplerates[] = {
	SR_HZ(1),
	SR_HZ(2),
	SR_HZ(5),
	SR_HZ(10),
	SR_HZ(20),
	SR_HZ(50),
	SR_HZ(100),
	SR_HZ(200),
	SR_HZ(500),
	SR_KHZ(1),
	SR_KHZ(2),
	SR_KHZ(5),
	SR_KHZ(10),
	SR_KHZ(20),
	SR_KHZ(50),
	SR_KHZ(100),
	SR_KHZ(200),
	SR_KHZ(500),
	SR_MHZ(1),
	0,
};

/* Timeout in milliseconds for USB bulk transfers. */
#define USB_CMD_TIMEOUT 50

static int send_cmd(struct dev_context *devc, uint8_t *cmdstring, int cmdlen)
{
	int ret, transferred;

	/* Send the command. */
	if ((ret = libusb_bulk_transfer(devc->usb->devhdl,
			EP_COMMAND_OUT,
			cmdstring, cmdlen,
			&transferred, USB_CMD_TIMEOUT)) != 0) {
		return ret;
	}

	/* Get the return value. */
	memset(cmdstring, 0, cmdlen);
	ret = libusb_bulk_transfer(
		devc->usb->devhdl,
		EP_COMMAND_RET,
		cmdstring, cmdlen,
		&transferred, USB_CMD_TIMEOUT);
	return ret;
}

SR_PRIV int polabs_poscope_mega1_open(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	uint8_t cmdstring[64];
	int ret;
	GString *firmware_date, *firmware_ver;
	unsigned int i, j;

	/* Reset? */
	sr_spew("Sending CMD_RESET.");
	memset(cmdstring, 0, 10);
	cmdstring[0] = CMD_RESET;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed to reset: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	/* Get firmware version */
	sr_spew("Sending CMD_FRM_VER.");
	memset(cmdstring, 0, 10);
	cmdstring[0] = CMD_FRM_VER;
	cmdstring[9] = 0xdd;  /* don't know why */
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed to get firmware version: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	/* PoScope does it twice */
	sr_spew("Sending CMD_FRM_VER.");
	memset(cmdstring, 0, 10);
	cmdstring[0] = CMD_FRM_VER;
	cmdstring[9] = 0xdd;  /* don't know why */
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed to get firmware version: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	/* Convert the firmware date into a string */
	firmware_date = g_string_new("");
	g_string_printf(firmware_date, "%02x%02x-%02x-%02x",
					cmdstring[5], cmdstring[6], cmdstring[4], cmdstring[3]);
	sr_dbg("Firmware date = '%s'", firmware_date->str);
	g_string_free(firmware_date, TRUE);

	/* Convert the firmware version into a string */
	firmware_ver = g_string_new("");
	g_string_printf(firmware_ver, "%x.%02x", cmdstring[7], cmdstring[8]);
	sr_dbg("Firmware version = '%s'", firmware_ver->str);
	g_string_free(firmware_ver, TRUE);

	/* No idea what these commands do. */
	uint8_t cmdstrings[][5] = {
		{ 0x5c, 0x00, 0x3f, 0x00, 0x00 },
		{ 0x5c, 0x00, 0x3f, 0x00, 0x3f },
		{ 0x5c, 0x00, 0x3f, 0x00, 0x7e },
		{ 0x5c, 0x00, 0x3f, 0x00, 0xbd },
		{ 0x5c, 0x00, 0x3f, 0x00, 0xfc },
		{ 0x5c, 0x00, 0x3f, 0x01, 0x3b },
		{ 0x5c, 0x00, 0x3f, 0x01, 0x7a },
		{ 0x5c, 0x00, 0x3f, 0x01, 0xb9 },
		{ 0x5c, 0x00, 0x3f, 0x01, 0xf8 },
		{ 0x5c, 0x00, 0x3f, 0x02, 0x37 },
		{ 0x5c, 0x00, 0x3f, 0x02, 0x76 },
		{ 0x5c, 0x00, 0x3f, 0x02, 0xb5 },
		{ 0x5c, 0x00, 0x3f, 0x02, 0xf4 },
		{ 0x5c, 0x00, 0x3f, 0x03, 0x33 },
		{ 0x5c, 0x00, 0x3f, 0x03, 0x72 },
		{ 0x5c, 0x00, 0x3f, 0x03, 0xb1 },
		{ 0x5c, 0x00, 0x10, 0x03, 0xf0 }
	};
	for (i = 0; i < ARRAY_SIZE(cmdstrings); i++) {
		memset(cmdstring, 0, 64);
		for (j = 0; j < 5; j++)
			cmdstring[j] = cmdstrings[i][j];
		send_cmd(devc, cmdstring, 64);
	}

	return SR_OK;
}

SR_PRIV int polabs_poscope_mega1_set_samplerate(const struct sr_dev_inst *sdi, uint64_t samplerate)
{
	struct dev_context *devc = sdi->priv;
	uint8_t freq_selector;
	unsigned int i;

	/* Frequency selector */
	freq_selector = 0;
	for (i = 0; i < ARRAY_SIZE(polabs_poscope_mega1_samplerates); i++) {
		if (polabs_poscope_mega1_samplerates[i] == samplerate) {
			freq_selector = 0x21 - i;
			break;
		}
	}
	if (freq_selector == 0) {
		sr_err("Unsupported samplerate.");
		return SR_ERR_SAMPLERATE;
	}

	devc->samplerate = samplerate;
	devc->freq_selector = freq_selector;

	return SR_OK;
}

SR_PRIV void polabs_poscope_mega1_stop(struct dev_context *devc)
{
	unsigned int i;

	devc->num_samples = -1;

	for (i = 0; i < ARRAY_SIZE(devc->transfers); i++) {
		if (devc->transfers[i]) {
			sr_dbg("Canceling transfer %i.", i);
			libusb_cancel_transfer(devc->transfers[i]);
		}
	}
}

static void free_transfer(struct libusb_transfer *transfer)
{
	struct dev_context *devc;
	unsigned int i;

	devc = transfer->user_data;

	g_free(transfer->buffer);
	transfer->buffer = NULL;
	libusb_free_transfer(transfer);

	for (i = 0; i < ARRAY_SIZE(devc->transfers); i++) {
		if (devc->transfers[i] == transfer) {
			sr_dbg("Freed transfer %i.", i);
			devc->transfers[i] = NULL;
			break;
		}
	}
}

static void resubmit_transfer(struct libusb_transfer *transfer)
{
	int ret;

	if ((ret = libusb_submit_transfer(transfer)) != LIBUSB_SUCCESS) {
		free_transfer(transfer);
		/* TODO: Stop session? */
		sr_err("%s: %s", __func__, libusb_error_name(ret));
	}
}

static void send_analog_packet(struct dev_context *devc, unsigned char *buf,
		int num_samples)
{
	struct sr_datafeed_packet packet;
	struct sr_datafeed_analog analog;
	unsigned int sample;
	float ch1;
	//float ch1, ch2, range;
	int num_probes, data_offset, i;

	//num_probes = (devc->analog_probe_enabled[0] && devc->analog_probe_enabled[1]) ? 2 : 1;
	num_probes = 1;
	packet.type = SR_DF_ANALOG;
	packet.payload = &analog;
	analog.probes = devc->enabled_probes;
	analog.num_samples = num_samples;
	analog.mq = SR_MQ_VOLTAGE;
	analog.unit = SR_UNIT_VOLT;
	/* TODO: Check malloc return value. */
	analog.data = g_try_malloc(analog.num_samples * sizeof(float) * num_probes);
	data_offset = 0;
	for (i = 0; i < analog.num_samples; i++) {
#if 0
		/*
		 * The device always sends data for both channels. If a channel
		 * is disabled, it contains a copy of the enabled channel's
		 * data. However, we only send the requested channels to
		 * the bus. TODO
		 *
		 * Voltage values are encoded as...
		 */
		if (devc->analog_probe_enabled[0]) {
			range = ((float)vdivs[devc->voltage_ch1].p / vdivs[devc->voltage_ch1].q) * 8;
			ch1 = range / 255 * *(buf + i * 2 + 1);
			/* Value is centered around 0V. */
			ch1 -= range / 2;
			analog.data[data_offset++] = ch1;
		}
		if (devc->analog_probe_enabled[1]) {
			range = ((float)vdivs[devc->voltage_ch2].p / vdivs[devc->voltage_ch2].q) * 8;
			ch2 = range / 255 * *(buf + i * 2);
			ch2 -= range / 2;
			analog.data[data_offset++] = ch2;
		}
#else
		sample = buf[i * 3] << 16 | buf[i * 3 + 1] << 8 | buf[i * 3 + 2];
		ch1 = ((float) (sample - 0x800000)) / 0x1000000 * 20.0;
		sr_spew("My value is %f", ch1);
		analog.data[data_offset++] = ch1;
#endif
	}
	sr_session_send(devc->cb_data, &packet);
}

static void receive_transfer(struct libusb_transfer *transfer)
{
	struct dev_context *devc;
	int sample_width, cur_sample_count;
	gboolean packet_has_error = FALSE;
	//struct sr_datafeed_packet packet;
	//struct sr_datafeed_logic logic;
	//int trigger_offset, i;
	//int trigger_offset_bytes;
	uint8_t *cur_buf;

	devc = transfer->user_data;

	/*
	 * If acquisition has already ended, just free any queued up
	 * transfer that come in.
	 */
	if (devc->num_samples == -1) {
		free_transfer(transfer);
		return;
	}

	/* Save incoming transfer before reusing the transfer struct. */
	cur_buf = transfer->buffer;
	sr_spew("len=%d stat=%d %02x %02x %02x %02x %02x %02x %02x %02x",
			transfer->actual_length, transfer->status,
			cur_buf[0], cur_buf[1], cur_buf[2], cur_buf[3],
			cur_buf[4], cur_buf[5], cur_buf[6], cur_buf[7]);
	sample_width = 3;  // TODO really?
	cur_sample_count = transfer->actual_length / sample_width;

	switch (transfer->status) {
	case LIBUSB_TRANSFER_NO_DEVICE:
		polabs_poscope_mega1_stop(devc);
		//free_transfer(transfer);
		return;
	case LIBUSB_TRANSFER_COMPLETED:
	case LIBUSB_TRANSFER_TIMED_OUT: /* We may have received some data though. */
		break;
	default:
		packet_has_error = TRUE;
		break;
	}

	if (transfer->actual_length == 0 || packet_has_error) {
		resubmit_transfer(transfer);
		return;
	}

#if 0
	trigger_offset = 0;
	if (devc->trigger_stage >= 0) {
		for (i = 0; i < cur_sample_count; i++) {

			const uint16_t cur_sample = devc->sample_wide ?
				*((const uint16_t*)cur_buf + i) :
				*((const uint8_t*)cur_buf + i);

			if ((cur_sample & devc->trigger_mask[devc->trigger_stage]) ==
				devc->trigger_value[devc->trigger_stage]) {
				/* Match on this trigger stage. */
				devc->trigger_buffer[devc->trigger_stage] = cur_sample;
				devc->trigger_stage++;

				if (devc->trigger_stage == NUM_TRIGGER_STAGES ||
					devc->trigger_mask[devc->trigger_stage] == 0) {
					/* Match on all trigger stages, we're done. */
					trigger_offset = i + 1;

					/*
					 * TODO: Send pre-trigger buffer to session bus.
					 * Tell the frontend we hit the trigger here.
					 */
					packet.type = SR_DF_TRIGGER;
					packet.payload = NULL;
					sr_session_send(devc->session_dev_id, &packet);

					/*
					 * Send the samples that triggered it,
					 * since we're skipping past them.
					 */
					packet.type = SR_DF_LOGIC;
					packet.payload = &logic;
					logic.unitsize = sizeof(*devc->trigger_buffer);
					logic.length = devc->trigger_stage * logic.unitsize;
					logic.data = devc->trigger_buffer;
					sr_session_send(devc->session_dev_id, &packet);

					devc->trigger_stage = TRIGGER_FIRED;
					break;
				}
			} else if (devc->trigger_stage > 0) {
				/*
				 * We had a match before, but not in the next sample. However, we may
				 * have a match on this stage in the next bit -- trigger on 0001 will
				 * fail on seeing 00001, so we need to go back to stage 0 -- but at
				 * the next sample from the one that matched originally, which the
				 * counter increment at the end of the loop takes care of.
				 */
				i -= devc->trigger_stage;
				if (i < -1)
					i = -1; /* Oops, went back past this buffer. */
				/* Reset trigger stage. */
				devc->trigger_stage = 0;
			}
		}
	}

	if (devc->trigger_stage == TRIGGER_FIRED) {
		/* Send the incoming transfer to the session bus. */
		trigger_offset_bytes = trigger_offset * sample_width;
		packet.type = SR_DF_LOGIC;
		packet.payload = &logic;
		logic.length = transfer->actual_length - trigger_offset_bytes;
		logic.unitsize = sample_width;
		logic.data = cur_buf + trigger_offset_bytes;
		sr_session_send(devc->session_dev_id, &packet);

		devc->num_samples += cur_sample_count;
		if (devc->limit_samples &&
			(unsigned int)devc->num_samples > devc->limit_samples) {
			polabs_poscope_mega1_stop(devc);
			free_transfer(transfer);
			return;
		}
	} else {
		/*
		 * TODO: Buffer pre-trigger data in capture
		 * ratio-sized buffer.
		 */
	}
#else
	send_analog_packet(devc, transfer->buffer, cur_sample_count);
	devc->num_samples += cur_sample_count;
#endif

	resubmit_transfer(transfer);
}

static int setup_transfer_structs(struct dev_context *devc)
{
	size_t bufsize;
	unsigned int i;
	unsigned char *buf;
	unsigned int timeout;
	int ret;

	timeout = 1010;
	bufsize = 0x12C0;  // 4800
	for (i = 0; i < ARRAY_SIZE(devc->transfers); i++) {
		if (!(buf = g_try_malloc(bufsize))) {
			sr_err("USB transfer buffer malloc failed.");
			return SR_ERR_MALLOC;
		}
		devc->transfers[i] = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(devc->transfers[i], devc->usb->devhdl,
				EP_DATA_RETURN, buf, bufsize,
				receive_transfer, devc, timeout);
		if ((ret = libusb_submit_transfer(devc->transfers[i])) != 0) {
			sr_err("Failed to submit transfer: %s.", libusb_error_name(ret));
			libusb_free_transfer(devc->transfers[i]);
			g_free(buf);
			polabs_poscope_mega1_stop(devc);
			return SR_ERR;
		}
	}

	return SR_OK;
}

SR_PRIV int polabs_poscope_mega1_start(struct dev_context *devc, void *cb_data)
{
	uint8_t cmdstring[32];
	int ret, i;

	devc->cb_data = cb_data;

	sr_spew("Sending CMD_LOG_STOP.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_LOG_STOP;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_LOG_STOP: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	sr_spew("Sending CMD_OSC_STOP.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_OSC_STOP;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_OSC_STOP: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	sr_spew("Sending CMD_OSC_FREQ.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_OSC_FREQ;
	cmdstring[1] = devc->freq_selector;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_OSC_FREQ: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	for (i = 0; i < 2; i++) {
		sr_spew("Sending CMD_OSC_ACDC.");
		memset(cmdstring, 0, sizeof(cmdstring));
		cmdstring[0] = CMD_OSC_ACDC;
		cmdstring[1] = (uint8_t) i + 1;
		cmdstring[2] = 0x02;
		if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
			sr_err("Failed CMD_OSC_ACDC: %s.", libusb_error_name(ret));
			return SR_ERR;
		}
	}

	for (i = 0; i < 2; i++) {
		/* TODO Why do we send this CLEAR_FEATURE here? */
		sr_spew("Sending to EP0.");
		if ((ret = libusb_control_transfer(devc->usb->devhdl,
				LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_ENDPOINT,
				LIBUSB_REQUEST_CLEAR_FEATURE,
				0,
				0x82,
				NULL,
				0,
				USB_CMD_TIMEOUT)) < 0) {
			sr_err("Failed control 82: %s.", libusb_error_name(ret));
			return ret;
		}
		if ((ret = libusb_control_transfer(devc->usb->devhdl,
				LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_ENDPOINT,
				LIBUSB_REQUEST_CLEAR_FEATURE,
				0,
				0x85,
				NULL,
				0,
				USB_CMD_TIMEOUT)) < 0) {
			sr_err("Failed control 85: %s.", libusb_error_name(ret));
			return ret;
		}
		sr_spew("Sending CMD_OSC_ONOFF.");
		memset(cmdstring, 0, sizeof(cmdstring));
		cmdstring[0] = CMD_OSC_ONOFF;
		cmdstring[1] = (uint8_t) i + 1;
		cmdstring[2] = devc->analog_probe_enabled[i] ? 0x01: 0x00;
		if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
			sr_err("Failed CMD_OSC_ONOFF: %s.", libusb_error_name(ret));
			return SR_ERR;
		}
	}

	for (i = 0; i < 2; i++) {
		sr_spew("Sending CMD_OSC_DIV.");
		memset(cmdstring, 0, sizeof(cmdstring));
		cmdstring[0] = CMD_OSC_DIV;
		cmdstring[1] = (uint8_t) i + 1;
		if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
			sr_err("Failed CMD_OSC_DIV: %s.", libusb_error_name(ret));
			return SR_ERR;
		}
	}

	for (i = 0; i < 2; i++) {
		sr_spew("Sending CMD_LOG_PCFG.");
		memset(cmdstring, 0, sizeof(cmdstring));
		cmdstring[0] = CMD_LOG_PCFG;
		cmdstring[1] = (uint8_t) i + 1;
		cmdstring[2] = 0x55;
		cmdstring[3] = 0x55;
		if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
			sr_err("Failed CMD_LOG_PCFG: %s.", libusb_error_name(ret));
			return SR_ERR;
		}
	}

	sr_spew("Sending CMD_OSC_RUN.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_OSC_RUN;
	cmdstring[1] = 0x02;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_OSC_RUN: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	sr_spew("Sending CMD_OSC_TRG.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_OSC_TRG;
	cmdstring[1] = 0xff;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_OSC_TRG: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	sr_spew("Sending CMD_LOG_STOP.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_LOG_STOP;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_LOG_STOP: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	sr_spew("Sending CMD_OSC_RUN.");
	memset(cmdstring, 0, sizeof(cmdstring));
	cmdstring[0] = CMD_OSC_RUN;
	cmdstring[1] = 0x02;
	if ((ret = send_cmd(devc, cmdstring, 10)) != 0) {
		sr_err("Failed CMD_OSC_RUN: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	// call from handle_event?
	// polabs_poscope_mega1_receive_data(int fd, int revents, void *cb_data)

	//devc->num_samples = 0;

	if ((ret = setup_transfer_structs(devc)) != SR_OK)
		return ret;

	return SR_OK;
}
