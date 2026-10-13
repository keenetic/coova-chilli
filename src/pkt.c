/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2007-2012 David Bird (Coova Technologies) <support@coova.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "chilli.h"

int pkt_shape_tcpwin(struct pkt_iphdr_t *iph, uint16_t win) {
  uint16_t hlen = (iph->version_ihl & 0xf) * 4;
  if (iph->protocol == PKT_IP_PROTO_TCP &&
      iphdr_offset(iph) == 0 &&
      ntohs(iph->tot_len) >= hlen + PKT_TCP_HLEN) {
    struct pkt_tcphdr_t *tcph =
        (struct pkt_tcphdr_t *)(((uint8_t *)iph) + hlen);
    /*log_dbg("TCP Window %d", ntohs(tcph->win));*/
    if (ntohs(tcph->win) > win) {
#if(_debug_ > 1)
      syslog(LOG_DEBUG, "Rewriting TCP Window %d", win);
#endif
      tcph->win = htons(win);
      chksum(iph);
    }
  }
  return 0;
}

int pkt_shape_tcpmss(uint8_t *packet, size_t *length) {
  int optval = _options.tcpmss;
  struct pkt_iphdr_t *iph = pkt_iphdr(packet);

  if (iph->protocol == PKT_IP_PROTO_TCP) {

    struct pkt_tcphdr_t *tcph = pkt_tcphdr(packet);
    int off = tcph->offres >> 4;
    int hasmss = 0;

#if(0)
    syslog(LOG_DEBUG, "-->> offset: %d", off);
#endif

    if (off > 15 || off < 5)
      return -1;

    if (iphdr_offset(iph) != 0 ||
        sizeofip(packet) + (off * 4) > *length)
      return -1;

    if (off > 5) {
      uint8_t *opts = tcph->options;
      uint8_t type;
      int len;
      int optlen = (off - 5) * 4;
      int done = 0;
      int i = 0;

      while (!done && i < optlen) {
	switch(type = opts[i++]) {
          case 0:
            done = 1;
            break;

          case 1:
#if(0)
            syslog(LOG_DEBUG, "TCP OPTIONS: NOP");
#endif
            break;

          default:
            if (i >= optlen) {
              syslog(LOG_ERR, "truncated TCP option during parse");
              return -1;
            }
            len = (int) opts[i++];
            if (len < 2 || len > TCP_MAX_OPTION_LEN ||
                i - 2 + len > optlen) {
              syslog(LOG_ERR, "bad TCP option during parse, len=%d", len);
              return -1;
            }
            if (type == 2 && len == 4) {
#if(1)
              syslog(LOG_DEBUG, "TCP OPTIONS: MSS %d",
                     ntohs(*((uint16_t *)&opts[i])));
#endif
              if (ntohs(*((uint16_t *)&opts[i])) > optval) {

                syslog(LOG_DEBUG, "Rewriting TCP MSS to %d", optval);

                *((uint16_t *)&opts[i]) = htons(optval);
                chksum(iph);
              }
              hasmss = 1;
#ifdef ENABLE_LEAKYBUCKET
            } else if (_options.scalewin && type == 3 && len == 3) {
              syslog(LOG_DEBUG, "TCP OPTIONS: window scale was %d",
                     (int) opts[i]);
              if (opts[i] > 0) {
                opts[i]=0;
                chksum(iph);
              }
#endif
            } else {
#if(0)
              syslog(LOG_DEBUG, "TCP OPTIONS: type %d len %d", type, len);
#endif
            }
            i += len - 2;
            break;
	}
      }
    }

    if (!hasmss && off < 15 && *length < 1400 && tcphdr_syn(tcph)) {
      uint8_t p[PKT_BUFFER];
      memcpy(p, packet, *length);

      syslog(LOG_DEBUG, "Adding TCP MSS to %d", optval);

      {
	struct pkt_iphdr_t *p_iph = pkt_iphdr(p);
	struct pkt_tcphdr_t *p_tcph = pkt_tcphdr(p);

	uint8_t *dst_opt = p_tcph->options + ((off - 5) * 4);
	uint8_t *src_opt = tcph->options + ((off - 5) * 4);

	int dlen = *length - sizeofip(packet) - (off * 4);

	/*
	 *  log_dbg("TCP DATA: (%d - %d - %d) len %d",
	 *  *length, sizeofip(packet), (off * 4), dlen);
	 */

	/*
	 *  TODO: This should back up and find any type=0 NULL or padding.
	 */

	p_tcph->offres = (off + 1) << 4;

	dst_opt[0] = 2;
	dst_opt[1] = 4;

	*((uint16_t *)&dst_opt[2]) = htons(optval);

	if (dlen > 0) {
	  memcpy(dst_opt + 4, src_opt, dlen);
	}

	*length = *length + 4;
	p_iph->tot_len = htons(ntohs(p_iph->tot_len)+4);

	chksum(p_iph);

	memcpy(packet, p, *length);
      }
    }
  }

  return 0;
}

