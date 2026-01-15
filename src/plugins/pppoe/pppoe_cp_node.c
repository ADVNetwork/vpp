/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or pemplied.
 * See the License for the specific language governing permissions and
 * lpemitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <ppp/packet.h>
#include <pppoe/pppoe.h>

#define foreach_pppoe_cp_next        \
_(DROP, "error-drop")                  \
_(INTERFACE, "interface-output" )      \

typedef enum
{
#define _(s,n) PPPOE_CP_NEXT_##s,
  foreach_pppoe_cp_next
#undef _
    PPPOE_CP_N_NEXT,
} pppoe_cp_next_t;

typedef struct {
  u32 next_index;
  u32 sw_if_index;
  u32 cp_if_index;
  u8 pppoe_code;
  u16 ppp_proto;
  u32 error;
} pppoe_cp_trace_t;

static u8 * format_pppoe_cp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_cp_trace_t * t = va_arg (*args, pppoe_cp_trace_t *);
  pppoe_main_t * pem = &pppoe_main;

  if ((t->sw_if_index >= vec_len (pem->dp_if_index_by_sw_if_index)) ||
	  (~0 == pem->dp_if_index_by_sw_if_index[t->sw_if_index]))
    {
      s = format (s, "PPPoE dispatch from sw_if_index %d next %d error %d \n"
	          "  pppoe_code 0x%x  ppp_proto 0x%x",
                  t->sw_if_index, t->next_index, t->error,
		  t->pppoe_code, t->ppp_proto);
    }
  else
    {
      s = format (s, "PPPoE dispatch from cp_if_index %d next %d error %d \n"
	          "  pppoe_code 0x%x  ppp_proto 0x%x",
                  t->cp_if_index, t->next_index, t->error,
		  t->pppoe_code, t->ppp_proto);
    }
  return s;
}

static void
handle_ipcp_configure_nak (vnet_main_t *vnm, pppoe_header_t *pppoe0,
			   ethernet_header_t *h0, u8 *ipcp_packet)
{
  u8 *options = ipcp_packet + 4;
  u8 *end = ipcp_packet + clib_net_to_host_u16 (*(u16 *) (ipcp_packet + 2));
  vnet_pppoe_add_del_session_args_t a;
  clib_memset (&a, 0, sizeof (a));

  a.is_add = true;
  a.session_id = ntohs (pppoe0->session_id);
  clib_memcpy (a.client_mac, h0->dst_address, 6);
  clib_memcpy (a.local_mac, h0->src_address, 6);

  while (options < end)
    {
      u8 option_type = options[0];
      u8 option_length = options[1];

      if (option_type == PPP_IPCP_OPTION_IP_ADDRESS &&
	  option_length == PPP_IPCP_OPTION_IP_ADDRESS_LENGTH)
	{
	  u8 *ip_address = options + 2;

	  ip4_main_t *ipm = &ip4_main;
	  uword *p = hash_get (ipm->fib_index_by_table_id, 0);
	  a.decap_fib_index = p[0];
	  a.client_ip = to_ip46 (false, ip_address);
	}

      options += option_length;
    }

  vl_api_rpc_call_main_thread (vnet_pppoe_add_del_session_cb, (u8 *) &a,
			       sizeof (a));
}

static void
handle_lcp_packet (vnet_main_t *vnm, pppoe_header_t *pppoe0,
		   ethernet_header_t *h0)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_entry_key_t cached_key = { 0 };
  pppoe_entry_key_t key = { 0 };
  pppoe_entry_result_t cached_result = { 0 };
  pppoe_entry_result_t result = { 0 };
  u32 bucket = 0;

  if (pppoe0->ppp_proto != clib_host_to_net_u16 (PPP_PROTOCOL_lcp))
    {
      return;
    }

  u8 *lcp_packet = (u8 *) (pppoe0 + 1);
  u8 code = lcp_packet[0];

  u8 *mac_address =
    (code == PPP_LCP_ECHO_REQUEST) ? h0->src_address : h0->dst_address;

  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
		  mac_address, pppoe0->session_id, &key, &bucket, &result);

  if (result.fields.session_index == ~0)
    {
      return;
    }

  pppoe_session_t *session =
    pool_elt_at_index (pem->sessions, result.fields.session_index);

  if (code == PPP_LCP_ECHO_REQUEST)
    session->lcp_echo_cnt++;
  else
    session->lcp_echo_reply_cnt++;

  if ((session->lcp_echo_cnt <= session->lcp_echo_reply_cnt) ||
      ((session->lcp_echo_cnt - session->lcp_echo_reply_cnt) < 2))
    {
      return;
    }

  vnet_pppoe_add_del_session_args_t a;
  clib_memset (&a, 0, sizeof (a));

  a.is_add = false;
  a.session_id = clib_net_to_host_u16 (pppoe0->session_id);
  a.client_ip = session->client_ip;
  clib_memcpy (a.client_mac, mac_address, 6);

  vl_api_rpc_call_main_thread (vnet_pppoe_add_del_session_cb, (u8 *) &a,
			       sizeof (a));
}

static void
handle_padt_packet (vnet_main_t *vnm, pppoe_header_t *pppoe0,
		    ethernet_header_t *h0)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_entry_key_t cached_key = { 0 };
  pppoe_entry_key_t key = { 0 };
  pppoe_entry_result_t cached_result = { 0 };
  pppoe_entry_result_t result = { 0 };
  u32 bucket = 0;

  u16 session_id = clib_net_to_host_u16 (pppoe0->session_id);
  u8 *mac = h0->dst_address;

  if (pppoe0->code != PPPOE_PADT)
    {
      return;
    }

  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result, mac,
		  pppoe0->session_id, &key, &bucket, &result);

  if (result.fields.session_index == ~0)
    {
      return;
    }

  pppoe_session_t *session =
    pool_elt_at_index (pem->sessions, result.fields.session_index);

  vnet_pppoe_add_del_session_args_t a;
  clib_memset (&a, 0, sizeof (a));

  a.is_add = false;
  a.session_id = session_id;
  a.client_ip = session->client_ip;
  clib_memcpy (a.client_mac, mac, 6);

  vl_api_rpc_call_main_thread (vnet_pppoe_add_del_session_cb, (u8 *) &a,
			       sizeof (a));
}

static void
handle_ipcp_packet (vnet_main_t *vnm, pppoe_header_t *pppoe0,
		    ethernet_header_t *h0)
{
  u8 *packet = (u8 *) (pppoe0 + 1);
  u8 code = packet[0];

  if (pppoe0->ppp_proto == clib_host_to_net_u16 (PPP_PROTOCOL_IPCP) &&
      code == PPP_IPCP_CONFIGURE_NAK)
    {
      handle_ipcp_configure_nak (vnm, pppoe0, h0, packet);
    }
}

static void
handle_ipv6cp_configure_nak (vnet_main_t *vnm, pppoe_header_t *pppoe0,
			     ethernet_header_t *h0, u8 *packet,
			     pppoe_main_t *pem)
{
  u8 *options = packet + 4; // Skip Code, Identifier, and Length fields
  u8 *end = packet + clib_net_to_host_u16 (*(u16 *) (packet + 2));

  u16 session_id = clib_net_to_host_u16 (pppoe0->session_id);

  while (options < end)
    {
      u8 option_type = options[0];
      u8 option_length = options[1];

      if (option_type == PPP_IPV6CP_OPTION_INTERFACE_IDENTIFIER &&
	  option_length == PPP_IPV6CP_OPTION_INTERFACE_IDENTIFIER_LENGTH)
	{
	  u8 *iid = options + 2;

	  vec_validate_init_empty (pem->ip6_ident_by_session_id, session_id,
				   0);
	  pem->ip6_ident_by_session_id[session_id] = *((u64 *) iid);
	}

      options += option_length;
    }
}

static void
handle_ipv6cp_packet (vnet_main_t *vnm, pppoe_header_t *pppoe0,
		      ethernet_header_t *h0, pppoe_main_t *pem)
{
  u8 *packet = (u8 *) (pppoe0 + 1);
  u8 code = packet[0];

  if (pppoe0->ppp_proto == clib_host_to_net_u16 (PPP_PROTOCOL_IPV6CP) &&
      code == PPP_IPV6CP_CONFIGURE_NAK)
    {
      handle_ipv6cp_configure_nak (vnm, pppoe0, h0, packet, pem);
    }
}

static void
handle_icmpv6_ra_packet (vnet_main_t *vnm, ethernet_header_t *h0, u8 *packet,
			 u16 ipv6_payload_length, pppoe_main_t *pem,
			 u16 session_id)
{
  // Skip ICMPv6 header (8 bytes) and RA fields (8 bytes)
  u8 *options = packet + 16;
  u8 *end = packet + ipv6_payload_length; // Use the IPv6 payload length to
					  // calculate the end pointer

  vnet_pppoe_add_del_session_args_t a;
  clib_memset (&a, 0, sizeof (a));

  a.is_add = true;
  a.is_ip6 = true;
  a.session_id = session_id;
  clib_memcpy (a.client_mac, h0->dst_address, 6);
  clib_memcpy (a.local_mac, h0->src_address, 6);

  while (options < end)
    {
      u8 option_type = options[0];
      u8 option_length = options[1] * 8; // Length is in units of 8 bytes

      if (option_type == 3) // Prefix Information Option
	{
	  a.prefix_length = options[2];
	  u8 *prefix = options + 16;

	  ip6_address_t prefix_address;
	  clib_memset (&prefix_address, 0, sizeof (prefix_address));
	  clib_memcpy (prefix_address.as_u8, prefix, a.prefix_length / 8);

	  ip6_address_t client_ip6;
	  clib_memcpy (client_ip6.as_u8, prefix_address.as_u8, 8);
	  clib_memcpy (client_ip6.as_u8 + 8,
		       pem->ip6_ident_by_session_id + session_id, 8);

	  pem->ip6_ident_by_session_id[session_id] = ~0;

	  a.client_ip = to_ip46 (true, client_ip6.as_u8);
	}

      options += option_length;
    }

  vl_api_rpc_call_main_thread (vnet_pppoe_add_del_session_cb, (u8 *) &a,
			       sizeof (a));
}

static void
handle_ipv6_packet (vnet_main_t *vnm, pppoe_header_t *pppoe0,
		    ethernet_header_t *h0, pppoe_main_t *pem)
{
  u8 *packet = (u8 *) (pppoe0 + 1);
  u16 session_id = clib_net_to_host_u16 (pppoe0->session_id);

  if (pem->ip6_ident_by_session_id == 0 ||
      session_id >= vec_len (pem->ip6_ident_by_session_id) ||
      pem->ip6_ident_by_session_id[session_id] == ~0)
    {
      return;
    }

  if (pppoe0->ppp_proto == clib_host_to_net_u16 (PPP_PROTOCOL_ip6))
    {
      ip6_header_t *ip6 = (ip6_header_t *) packet;
      u16 ipv6_payload_length = clib_net_to_host_u16 (ip6->payload_length);

      if (ip6->protocol == IP_PROTOCOL_ICMP6)
	{
	  u8 *icmp6 = (u8 *) (ip6 + 1);
	  u8 icmp6_type = icmp6[0];

	  if (icmp6_type == ICMP6_router_advertisement)
	    {
	      handle_icmpv6_ra_packet (vnm, h0, icmp6, ipv6_payload_length,
				       pem, session_id);
	    }
	}
    }
}

VLIB_NODE_FN (pppoe_cp_dispatch_node) (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  pppoe_main_t * pem = &pppoe_main;
  vnet_main_t * vnm = pem->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  ethernet_header_t *h0;
	  pppoe_header_t * pppoe0;
	  pppoe_entry_key_t key0;
	  pppoe_entry_result_t result0;

	  u32 bucket0;
	  u32 next0;
          u32 error0 = 0;
	  u32 rx_sw_if_index0=~0, tx_sw_if_index0=~0, len0;
	  vnet_hw_interface_t *hi;
	  vnet_sw_interface_t *si;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          /* leaves current_data pointing at the pppoe header */
          pppoe0 = vlib_buffer_get_current (b0);
          rx_sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
	    {
	      error0 = PPPOE_ERROR_BAD_VER_TYPE;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }

          vlib_buffer_reset(b0);
          h0 = vlib_buffer_get_current (b0);

	  if (pem->is_auto_discovery)
	    {
	      handle_ipcp_packet (vnm, pppoe0, h0);
	      handle_lcp_packet (vnm, pppoe0, h0);
	      handle_padt_packet (vnm, pppoe0, h0);
	      handle_ipv6cp_packet (vnm, pppoe0, h0, pem);
	      handle_ipv6_packet (vnm, pppoe0, h0, pem);
	    }

          if ((rx_sw_if_index0 < vec_len (pem->dp_if_index_by_sw_if_index)) &&
            (~0 != pem->dp_if_index_by_sw_if_index[rx_sw_if_index0]))
            {
    	      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result,
    			      h0->dst_address, 0,
    			      &key0, &bucket0, &result0);
    	      tx_sw_if_index0 = result0.fields.sw_if_index;

              if (PREDICT_FALSE (tx_sw_if_index0 == ~0))
    	        {
    	          error0 = PPPOE_ERROR_NO_SUCH_SESSION;
    	          next0 = PPPOE_INPUT_NEXT_DROP;
    	          goto trace00;
    	        }

              next0 = PPPOE_CP_NEXT_INTERFACE;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;

              /* set src mac address */
              si = vnet_get_sw_interface(vnm, tx_sw_if_index0);
              if( si->type == VNET_SW_INTERFACE_TYPE_SUB ) {
                si = vnet_get_sw_interface(vnm, si->sup_sw_if_index);
              }
              hi = vnet_get_hw_interface (vnm, si->hw_if_index);
              clib_memcpy_fast (vlib_buffer_get_current (b0)+6, hi->hw_address, 6);
            }
          else
            {
    	      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result,
    			      h0->src_address, 0,
    			      &key0, &bucket0, &result0);
    	      tx_sw_if_index0 = result0.fields.sw_if_index;

              /* learn client session */
    	      pppoe_learn_process (&pem->link_table, rx_sw_if_index0,
				   &key0, &cached_key,
    			           &bucket0, &result0);

              next0 = PPPOE_CP_NEXT_INTERFACE;
              if ((rx_sw_if_index0 < vec_len (pem->cp_if_index_by_sw_if_index)) &&
            (~0 != pem->cp_if_index_by_sw_if_index[rx_sw_if_index0]))
                {
                  vnet_buffer(b0)->sw_if_index[VLIB_TX] = pem->cp_if_index_by_sw_if_index[rx_sw_if_index0];
                }
              else
                {
                  error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                  next0 = PPPOE_INPUT_NEXT_DROP;
                  goto trace00;
                }
            }

	  len0 = vlib_buffer_length_in_chain (vm, b0);

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

	  /* Batch stats increment on the same pppoe session so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (rx_sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = rx_sw_if_index0;
	    }
        
        trace00:  
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_cp_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->sw_if_index = tx_sw_if_index0;
              if ((rx_sw_if_index0 < vec_len (pem->cp_if_index_by_sw_if_index)) &&
                (~0 != pem->cp_if_index_by_sw_if_index[rx_sw_if_index0]))
                {
              tr->cp_if_index = pem->cp_if_index_by_sw_if_index[rx_sw_if_index0];
                }
              tr->pppoe_code = pppoe0->code;
              tr->ppp_proto = clib_net_to_host_u16(pppoe0->ppp_proto);
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that session tx stats is kept? */
  vlib_node_increment_counter (vm, pppoe_input_node.index,
                               PPPOE_ERROR_DECAPSULATED,
                               pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoe_cp_dispatch_node) = {
  .name = "pppoe-cp-dispatch",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PPPOE_N_ERROR,
  .error_strings = pppoe_error_strings,

  .n_next_nodes = PPPOE_CP_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_CP_NEXT_##s] = n,
    foreach_pppoe_cp_next
#undef _
  },

  .format_trace = format_pppoe_cp_trace,
};

