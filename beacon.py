#!/usr/bin/env python

# The MIT License (MIT) Copyright (c) 2016 GomSpace ApS

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# GOMX-3 beacon parser

from __future__ import print_function

import struct
import codecs


class Beacon0():
    BEACON0_LENGTH = 136
    BEACON0_SOURCE = 1
    BEACON0_DEST = 10
    BEACON0_DPORT = 30

    def __init__(self, data, csp=True, crc=True):

        # Split into CSP header and beacon data
        if csp:
            hdata, bdata = data[:4], data[4:]
            header = struct.unpack("<I", hdata)[0]

            # Verify that destination is beacon receiver
            src = (header >> 25) & 0x1f
            dst = (header >> 20) & 0x1f
            dport = (header >> 14) & 0x3f

            if src != self.BEACON0_SOURCE or dst != self.BEACON0_DEST or dport != self.BEACON0_DPORT:
                raise TypeError("Beacon destination does not match")
        else:
            bdata = data

        # Strip CRC (TODO: verify)
        if crc:
            bdata = bdata[:-4]

        if len(bdata) != self.BEACON0_LENGTH:
            raise TypeError("Length does not match beacon 0")

        # Split beacon fields
        btype, eps, com, obc, adcs, adsb = struct.unpack('<B49s14s14s20s38s', bdata)

        # Only beacon 0 is handled
        if btype != 0:
            raise TypeError('Unknown beacon type')

        # Beacon dictionary
        self.beacon = {}

        # EPS
        """
        uint32_t eps_timestamp;
        uint16_t eps_vboost_0;
        uint16_t eps_vboost_1;
        uint16_t eps_vboost_2;
        uint16_t eps_vbatt;
        uint16_t eps_curout_0;
        uint16_t eps_curout_1;
        uint16_t eps_curout_2;
        uint16_t eps_curout_3;
        uint16_t eps_curout_4;
        uint16_t eps_curout_5;
        uint16_t eps_curout_6;
        uint16_t eps_curin_0;
        uint16_t eps_curin_1;
        uint16_t eps_curin_2;
        uint16_t eps_cursun;
        uint16_t eps_cursys;
        int16_t  eps_temp_0;
        int16_t  eps_temp_1;
        int16_t  eps_temp_2;
        int16_t  eps_temp_3;
        int16_t  eps_temp_4;
        int16_t  eps_temp_5;
        uint8_t  eps_battmode;
        """
        eps_timestamp, \
        eps_vboost_0, \
        eps_vboost_1, \
        eps_vboost_2, \
        eps_vbatt, \
        eps_curout_0, \
        eps_curout_1, \
        eps_curout_2, \
        eps_curout_3, \
        eps_curout_4, \
        eps_curout_5, \
        eps_curout_6, \
        eps_curin_0, \
        eps_curin_1, \
        eps_curin_2, \
        eps_cursun, \
        eps_cursys, \
        eps_temp_0, \
        eps_temp_1, \
        eps_temp_2, \
        eps_temp_3, \
        eps_temp_4, \
        eps_temp_5, \
        eps_battmode \
        = struct.unpack('>I16H6hB', eps)

        self.beacon['eps'] = {
            'timestamp': eps_timestamp,
            'vboost': (eps_vboost_0, eps_vboost_1, eps_vboost_2),
            'vbatt': eps_vbatt,
            'curout': (eps_curout_0, eps_curout_1, eps_curout_2, eps_curout_3, eps_curout_4, eps_curout_5, eps_curout_6),
            'curin': (eps_curin_0, eps_curin_1, eps_curin_2),
            'cursun': eps_cursun,
            'cursys': eps_cursys,
            'temp': (eps_temp_0, eps_temp_1, eps_temp_2, eps_temp_3, eps_temp_4, eps_temp_5),
            'battmode': eps_battmode}

        # COM
        """
        uint32_t com_timestamp;
        int16_t  com_temp_brd;
        int16_t  com_temp_pa;
        int16_t  com_last_rssi;
        int16_t  com_last_rferr;
        int16_t  com_bgnd_rssi;
        """
        com_timestamp, \
        com_temp_brd, \
        com_temp_pa, \
        com_last_rssi, \
        com_last_rferr, \
        com_bgnd_rssi \
        = struct.unpack('>I5h', com)

        self.beacon['com'] = {
            'timestamp': com_timestamp,
            'temp_brd': com_temp_brd / 10.0,
            'temp_pa': com_temp_pa / 10.0,
            'last_rssi': com_last_rssi,
            'last_rferr': com_last_rferr,
            'bgnd_rssi': com_bgnd_rssi}

        # OBC
        """
        uint32_t obc_timestamp;
        uint16_t obc_cur_gssb1;
        uint16_t obc_cur_gssb2;
        uint16_t obc_cur_flash;
        int16_t  obc_temp_a;
        int16_t  obc_temp_b;
        """
        obc_timestamp, \
        obc_cur_gssb1, \
        obc_cur_gssb2, \
        obc_cur_flash, \
        obc_temp_a, \
        obc_temp_b \
        = struct.unpack('>I3H2h', obc)

        self.beacon['obc'] = {
            'timestamp': obc_timestamp,
            'cur_gssb1': obc_cur_gssb1,
            'cur_gssb2': obc_cur_gssb2,
            'cur_flash': obc_cur_flash,
            'temp_a': obc_temp_a / 10.0,
            'temp_b ': obc_temp_b / 10.0}

        # ADCS
        """
        uint32_t adcs_timestamp;
        uint16_t adcs_cur_gssb1;
        uint16_t adcs_cur_gssb2;
        uint16_t adcs_cur_flash;
        uint16_t adcs_cur_pwm;
        uint16_t adcs_cur_gps;
        uint16_t adcs_cur_wde;
        int16_t  adcs_temp_a;
        int16_t  adcs_temp_b;
        """
        adcs_timestamp, \
        adcs_cur_gssb1, \
        adcs_cur_gssb2, \
        adcs_cur_flash, \
        adcs_cur_pwm, \
        adcs_cur_gps, \
        adcs_cur_wde, \
        adcs_temp_a, \
        adcs_temp_b \
        = struct.unpack('>I6H2h', adcs)

        self.beacon['adcs'] = {
            'timestamp': adcs_timestamp,
            'cur_gssb1': adcs_cur_gssb1,
            'cur_gssb2': adcs_cur_gssb2,
            'cur_flash': adcs_cur_flash,
            'cur_pwm': adcs_cur_pwm,
            'cur_gps': adcs_cur_gps,
            'cur_wde': adcs_cur_wde,
            'temp_a': adcs_temp_a / 10.0,
            'temp_b ': adcs_temp_b / 10.0}

        # ADS-B
        """
        uint32_t adsb_timestamp;
        uint16_t adsb_cur5v0brd;
        uint16_t adsb_cur3v3brd;
        uint16_t adsb_cur3v3sd;
        uint16_t adsb_cur1v2;
        uint16_t adsb_cur2v5;
        uint16_t adsb_cur3v3fpga;
        uint16_t adsb_cur3v3adc;
        uint32_t adsb_last_icao;
        float    adsb_last_lat;
        float    adsb_last_lon;
        uint32_t adsb_last_alt;
        uint32_t adsb_last_time;
        """
        adsb_timestamp, \
        adsb_cur5v0brd, \
        adsb_cur3v3brd, \
        adsb_cur3v3sd, \
        adsb_cur1v2, \
        adsb_cur2v5, \
        adsb_cur3v3fpga, \
        adsb_cur3v3adc, \
        adsb_last_icao, \
        adsb_last_lat, \
        adsb_last_lon, \
        adsb_last_alt, \
        adsb_last_time \
        = struct.unpack('>I7HI2f2I', adsb)

        self.beacon['adsb'] = {
            'timestamp': adsb_timestamp,
            'cur5v0brd': adsb_cur5v0brd,
            'cur3v3brd': adsb_cur3v3brd,
            'cur3v3sd': adsb_cur3v3sd,
            'cur1v2': adsb_cur1v2,
            'cur2v5': adsb_cur2v5,
            'cur3v3fpga': adsb_cur3v3fpga,
            'cur3v3adc': adsb_cur3v3adc,
            'last_icao': adsb_last_icao,
            'last_lat': adsb_last_lat,
            'last_lon': adsb_last_lon,
            'last_alt': adsb_last_alt,
            'last_time ': adsb_last_time}

    def fields(self):
        return self.beacon

if __name__ == '__main__':
    import json
    import base64

    data = base64.b64decode("ALn8/MQJQAlMCRlAzwCtAEEABABEAHAAAAACAAIAAwOeAHAAWwAcAB4AHgAdABwAHAO5/PzEATgBOf/F/5X/lbn8/MQAAAABAAAAAAE+ufz8xAACAAcAAAAEAA4AAAE6ATm5/PzEAMkAKAABAAYAFgAzABgARJLhQmBHPEEc02IAAHj/ufz8uUi0xsg=")

    b = Beacon0(data, csp=False, crc=True)

    print(json.dumps(b.fields(), sort_keys=True, indent=4))
