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

#ifndef LIBSIGROK_HARDWARE_POLABS_POSCOPE_MEGA1_PROTOCOL_H
#define LIBSIGROK_HARDWARE_POLABS_POSCOPE_MEGA1_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include "libsigrok.h"
#include "libsigrok-internal.h"

/* Message logging helpers with driver-specific prefix string. */
#define DRIVER_LOG_DOMAIN "polabs-poscope-mega1: "
#define sr_log(l, s, args...) sr_log(l, DRIVER_LOG_DOMAIN s, ## args)
#define sr_spew(s, args...) sr_spew(DRIVER_LOG_DOMAIN s, ## args)
#define sr_dbg(s, args...) sr_dbg(DRIVER_LOG_DOMAIN s, ## args)
#define sr_info(s, args...) sr_info(DRIVER_LOG_DOMAIN s, ## args)
#define sr_warn(s, args...) sr_warn(DRIVER_LOG_DOMAIN s, ## args)
#define sr_err(s, args...) sr_err(DRIVER_LOG_DOMAIN s, ## args)

/** Private, per-device-instance driver context. */
struct dev_context {
	struct sr_usb_dev_inst *usb;

	int dev_state;

	/** The current sampling rate (in Hertz). */
	uint64_t samplerate;

	/** The current frequency selector (derived from samplerate). */
	uint64_t freq_selector;

	/** The current sampling limit (in number of samples). */
	uint64_t limit_samples;

	/** The current sampling limit (in ms). */
	uint64_t limit_msec;

	/** Opaque pointer passed in by the frontend. */
	void *cb_data;

	/** The current number of already received samples. */
	int64_t num_samples;

	GSList *enabled_probes;
	gboolean ch1_enabled;
	gboolean ch2_enabled;

	/** USB transfer structures. */
	struct libusb_transfer *transfers[2];
};

extern SR_PRIV const uint64_t polabs_poscope_mega1_samplerates[];

SR_PRIV int polabs_poscope_mega1_open(const struct sr_dev_inst *sdi);
SR_PRIV int polabs_poscope_mega1_set_samplerate(const struct sr_dev_inst *sdi, uint64_t samplerate);
SR_PRIV int polabs_poscope_mega1_start(struct dev_context *devc, void *cb_data);
SR_PRIV void polabs_poscope_mega1_stop(struct dev_context *devc);

#endif
