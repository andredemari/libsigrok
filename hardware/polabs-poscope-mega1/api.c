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
#include "protocol.h"

#define POSCOPE_VENDOR "PoScope"
#define POSCOPE_MODEL "mega1+"
#define MEGA1_VID 0x1dc3
#define MEGA1_PID 0x04b1
#define MEGA1_USB_INTERFACE_NUM 0

SR_PRIV struct sr_dev_driver polabs_poscope_mega1_driver_info;
static struct sr_dev_driver *di = &polabs_poscope_mega1_driver_info;

static const int hwcaps[] = {
	SR_CONF_LOGIC_ANALYZER,
	SR_CONF_OSCILLOSCOPE,
	SR_CONF_SAMPLERATE,
	SR_CONF_CAPTURE_RATIO, /* TODO verify */
	SR_CONF_LIMIT_SAMPLES, /* TODO verify */
	SR_CONF_CONTINUOUS,
	0,
};

static const char *analog_probe_names[] = {
	"Ch.1", "Ch.2",
	NULL,
};

static const char *logic_probe_names[] = {  /* TODO check names */
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
	"13", "14", "15",
	NULL,
};

static const struct sr_samplerates samplerates = {
	.low  = 0,
	.high = 0,
	.step = 0,
	.list = polabs_poscope_mega1_samplerates,
};

static int hw_dev_acquisition_stop(struct sr_dev_inst *sdi, void *cb_data);

static int hw_dev_close(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;

	devc = sdi->priv;
	if (!devc->usb->devhdl)
		/* Nothing to do. */
		return SR_OK;

	libusb_release_interface(devc->usb->devhdl, MEGA1_USB_INTERFACE_NUM);
	libusb_close(devc->usb->devhdl);
	devc->usb->devhdl = NULL;
	/*g_free(devc->config); TODO */
	sdi->status = SR_ST_INACTIVE;

	return SR_OK;
}

/* Properly close and free all devices. */
static int clear_instances(void)
{
	struct sr_dev_inst *sdi;
	struct drv_context *drvc;
	struct dev_context *devc;
	GSList *l;

	if (!(drvc = di->priv))
		return SR_OK;

	for (l = drvc->instances; l; l = l->next) {
		if (!(sdi = l->data))
			continue;
		if (!(devc = sdi->priv))
			continue;

		hw_dev_close(sdi);
		sr_usb_dev_inst_free(devc->usb);
		sr_dev_inst_free(sdi);
	}

	g_slist_free(drvc->instances);
	drvc->instances = NULL;

	return SR_OK;
}

static int hw_init(struct sr_context *sr_ctx)
{
	return std_hw_init(sr_ctx, di, DRIVER_LOG_DOMAIN);
}

static GSList *hw_scan(GSList *options)
{
	struct drv_context *drvc;
	struct dev_context *devc;
	struct sr_dev_inst *sdi;
	GSList *devices;
	libusb_device **devlist;
	int i, j, ret;
	struct libusb_device_descriptor des;
	int devcnt;
	struct sr_probe *probe;

	(void) options;

	drvc = di->priv;

	/* USB scan is always authoritative. */
	clear_instances();

	devices = NULL;
	libusb_get_device_list(drvc->sr_ctx->libusb_ctx, &devlist);
	for (i = 0; devlist[i]; i++) {
		if ((ret = libusb_get_device_descriptor(devlist[i], &des)) != 0) {
			sr_warn("Failed to get device descriptor: %s",
					libusb_error_name(ret));
			continue;
		}

		if (des.idVendor != MEGA1_VID || des.idProduct != MEGA1_PID)
			continue;

		devcnt = g_slist_length(drvc->instances);
		if (!(sdi = sr_dev_inst_new(devcnt, SR_ST_INITIALIZING,
				POSCOPE_VENDOR, POSCOPE_MODEL, NULL)))
			return NULL;
		sdi->driver = di;

		if (!(devc = g_try_malloc0(sizeof(struct dev_context))))
			return NULL;
		sdi->priv = devc;

		/* Add analog probes. */
		for (j = 0; analog_probe_names[j]; j++) {
			if (!(probe = sr_probe_new(j, SR_PROBE_ANALOG, TRUE,
					analog_probe_names[j])))
				return NULL;
			sdi->probes = g_slist_append(sdi->probes, probe);
		}

		/* Add logic probes. */
		for (j = 0; logic_probe_names[j]; j++) {
			if (!(probe = sr_probe_new(j, SR_PROBE_LOGIC, TRUE,
					logic_probe_names[j])))
				return 0;
			sdi->probes = g_slist_append(sdi->probes, probe);
		}

		if (!(devc->usb = sr_usb_dev_inst_new(libusb_get_bus_number(devlist[i]),
				libusb_get_device_address(devlist[i]), NULL)))
			return NULL;

		drvc->instances = g_slist_append(drvc->instances, sdi);
		devices = g_slist_append(devices, sdi);
		sdi->status = SR_ST_INACTIVE;

	}
	libusb_free_device_list(devlist, 1);

	return devices;
}

static GSList *hw_dev_list(void)
{
	return ((struct drv_context *)(di->priv))->instances;
}

static int hw_dev_open(struct sr_dev_inst *sdi)
{
	struct drv_context *drvc;
	struct dev_context *devc;
	int ret;

	if (!(drvc = di->priv)) {
		sr_err("Driver was not initialized.");
		return SR_ERR;
	}

	devc = sdi->priv;
	if (sr_usb_open(drvc->sr_ctx->libusb_ctx, devc->usb) != SR_OK)
		return SR_ERR;

	if ((ret = libusb_claim_interface(devc->usb->devhdl, MEGA1_USB_INTERFACE_NUM))) {
		sr_err("Failed to claim interface: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	ret = polabs_poscope_mega1_open(sdi);

	sdi->status = SR_ST_ACTIVE;

	return ret;
}

static int hw_cleanup(void)
{
	struct drv_context *drvc;

	if (!(drvc = di->priv))
		/* Can get called on an unused driver, doesn't matter. */
		return SR_OK;

	clear_instances();
	g_free(drvc);
	di->priv = NULL;

	return SR_OK;
}

static int hw_config_get(int id, const void **value,
			const struct sr_dev_inst *sdi)
{
	(void)sdi;
	(void)value;

	switch (id) {
	/* TODO */
	default:
		return SR_ERR_ARG;
	}

	return SR_OK;
}

static int hw_config_set(int id, const void *value,
			 const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	int ret;

	if (!di->priv) {
		sr_err("Driver was not initialized.");
		return SR_ERR;
	}

	if (sdi->status != SR_ST_ACTIVE) {
		sr_err("Device inactive, can't set config options.");
		return SR_ERR;
	}

	devc = sdi->priv;
	ret = SR_OK;
	switch (id) {
	case SR_CONF_SAMPLERATE:
		ret = polabs_poscope_mega1_set_samplerate(sdi, *(const uint64_t *)value);
		break;
	case SR_CONF_LIMIT_SAMPLES:
		devc->limit_samples = *(const uint64_t *)value;
		sr_dbg("Setting sample limit to %" PRIu64 ".", devc->limit_samples);
		break;
	default:
		sr_err("Unknown hardware capability: %d.", id);
		ret = SR_ERR_ARG;
	}

	return ret;
}

static int hw_config_list(int key, const void **data,
			const struct sr_dev_inst *sdi)
{
	(void)sdi;

	switch (key) {
	case SR_CONF_DEVICE_OPTIONS:
		*data = hwcaps;
		break;
	case SR_CONF_SAMPLERATE:
		*data = &samplerates;
		break;
	default:
		return SR_ERR_ARG;
	}

	return SR_OK;
}

static void setup_enabled_probes(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_probe *probe;
	const GSList *l;
	int p;

	/* setup devc->enabled_probes and dev->ch[12]_enabled */
	devc = sdi->priv;

	g_slist_free(devc->enabled_probes);

	for (l = sdi->probes, p = 0; l; l = l->next, p++) {
		probe = l->data;
		if (p < 2)
			devc->analog_probe_enabled[p] = probe->enabled;
		if (probe->enabled)
			devc->enabled_probes = g_slist_append(devc->enabled_probes, probe);
	}
}

static int receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;
	struct drv_context *drvc;
	struct timeval tv;

	(void)fd;
	(void)revents;

	sdi = cb_data;
	devc = sdi->priv;

	if (devc->limit_samples &&
		(unsigned int)devc->num_samples > devc->limit_samples) {
		hw_dev_acquisition_stop((struct sr_dev_inst *)sdi, NULL);
	}

	if (sdi->status == SR_ST_STOPPING) {
		/* We've been told to wind up the acquisition. */
		return TRUE;
	}

	/* Always handle pending libusb events. */
	drvc = di->priv;
	tv.tv_sec = tv.tv_usec = 0;
	libusb_handle_events_timeout(drvc->sr_ctx->libusb_ctx, &tv);

	return TRUE;
}

static int hw_dev_acquisition_start(const struct sr_dev_inst *sdi, void *cb_data)
{
	struct drv_context *drvc;
	struct dev_context *devc;
	int ret;
	unsigned int timeout;
	unsigned int i;
	const struct libusb_pollfd **lupfd;

	(void) cb_data;

	drvc = di->priv;
	devc = sdi->priv;

	setup_enabled_probes(sdi);

	if ((ret = polabs_poscope_mega1_start(devc, cb_data)) != SR_OK) {
		return ret;
	}

	/* Send header packet to the session bus. */
	std_session_send_df_header(cb_data, DRIVER_LOG_DOMAIN);

	timeout = 1010;
	lupfd = libusb_get_pollfds(drvc->sr_ctx->libusb_ctx);
	for (i = 0; lupfd[i]; i++)
		sr_source_add(lupfd[i]->fd, lupfd[i]->events,
					timeout, receive_data, (void *)sdi);
	free(lupfd); /* NOT g_free()! */

	return SR_OK;
}

static int hw_dev_acquisition_stop(struct sr_dev_inst *sdi, void *cb_data)
{
	struct drv_context *drvc;
	struct dev_context *devc;
	const struct libusb_pollfd **lupfd;
	unsigned int i;
	struct sr_datafeed_packet packet;

	(void)cb_data;

	if (sdi->status != SR_ST_ACTIVE) {
		sr_err("Device inactive, can't stop acquisition.");
		return SR_ERR;
	}

	drvc = di->priv;
	devc = sdi->priv;

	sdi->status = SR_ST_STOPPING;
	polabs_poscope_mega1_stop(devc);

	/* Remove fds from polling. */
	lupfd = libusb_get_pollfds(drvc->sr_ctx->libusb_ctx);
	for (i = 0; lupfd[i]; i++)
		sr_source_remove(lupfd[i]->fd);
	free(lupfd); /* NOT g_free()! */

	packet.type = SR_DF_END;
	sr_session_send(sdi, &packet);

	return SR_OK;
}

SR_PRIV struct sr_dev_driver polabs_poscope_mega1_driver_info = {
	.name = "polabs-poscope-mega1",
	.longname = "PoLabs PoScope mega1+",
	.api_version = 1,
	.init = hw_init,
	.cleanup = hw_cleanup,
	.scan = hw_scan,
	.dev_list = hw_dev_list,
	.dev_clear = clear_instances,
	.config_get = hw_config_get,
	.config_set = hw_config_set,
	.config_list = hw_config_list,
	.dev_open = hw_dev_open,
	.dev_close = hw_dev_close,
	.dev_acquisition_start = hw_dev_acquisition_start,
	.dev_acquisition_stop = hw_dev_acquisition_stop,
	.priv = NULL,
};
