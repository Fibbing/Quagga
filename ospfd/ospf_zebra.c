/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#ifdef HAVE_SNMP
#include "ospfd/ospf_snmp.h"
#endif /* HAVE_SNMP */

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int
ospf_router_id_update_zebra (int command, struct zclient *zclient,
			     zebra_size_t length)
{
  struct ospf *ospf;
  struct prefix router_id;
  zebra_router_id_update_read(zclient->ibuf,&router_id);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    {
      char buf[128];
      prefix2str(&router_id, buf, sizeof(buf));
      zlog_debug("Zebra rcvd: router id update %s", buf);
    }

  router_id_zebra = router_id.u.prefix4;

  ospf = ospf_lookup ();

  if (ospf != NULL)
    ospf_router_id_update (ospf);

  return 0;
}

/* Inteface addition message from zebra. */
static int
ospf_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_debug ("Zebra: interface add %s index %d flags %llx metric %d mtu %d",
               ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
               ifp->metric, ifp->mtu);

  assert (ifp->info);

  if (!OSPF_IF_PARAM_CONFIGURED (IF_DEF_PARAMS (ifp), type))
    {
      SET_IF_PARAM (IF_DEF_PARAMS (ifp), type);
      IF_DEF_PARAMS (ifp)->type = ospf_default_iftype(ifp);
    }

  ospf_if_update (NULL, ifp);

#ifdef HAVE_SNMP
  ospf_snmp_if_update (ifp);
#endif /* HAVE_SNMP */

  return 0;
}

static int
ospf_interface_delete (int command, struct zclient *zclient,
                       zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;
  struct route_node *rn;

  s = zclient->ibuf;
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read (s);

  if (ifp == NULL)
    return 0;

  if (if_is_up (ifp))
    zlog_warn ("Zebra: got delete of %s, but interface is still up",
               ifp->name);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_debug
      ("Zebra: interface delete %s index %d flags %llx metric %d mtu %d",
       ifp->name, ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

#ifdef HAVE_SNMP
  ospf_snmp_if_delete (ifp);
#endif /* HAVE_SNMP */

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
    if (rn->info)
      ospf_if_free ((struct ospf_interface *) rn->info);

  ifp->ifindex = IFINDEX_INTERNAL;
  return 0;
}

static struct interface *
zebra_interface_if_lookup (struct stream *s)
{
  char ifname_tmp[INTERFACE_NAMSIZ];

  /* Read interface name. */
  stream_get (ifname_tmp, s, INTERFACE_NAMSIZ);

  /* And look it up. */
  return if_lookup_by_name_len(ifname_tmp,
			       strnlen(ifname_tmp, INTERFACE_NAMSIZ));
}

static int
ospf_interface_state_up (int command, struct zclient *zclient,
                         zebra_size_t length)
{
  struct interface *ifp;
  struct ospf_interface *oi;
  struct route_node *rn;

  ifp = zebra_interface_if_lookup (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  /* Interface is already up. */
  if (if_is_operative (ifp))
    {
      /* Temporarily keep ifp values. */
      struct interface if_tmp;
      memcpy (&if_tmp, ifp, sizeof (struct interface));

      zebra_interface_if_set_value (zclient->ibuf, ifp);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
        zlog_debug ("Zebra: Interface[%s] state update.", ifp->name);

      if (if_tmp.bandwidth != ifp->bandwidth)
        {
          if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
            zlog_debug ("Zebra: Interface[%s] bandwidth change %d -> %d.",
                       ifp->name, if_tmp.bandwidth, ifp->bandwidth);

          ospf_if_recalculate_output_cost (ifp);
        }

      if (if_tmp.mtu != ifp->mtu)
        {
          if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
            zlog_debug ("Zebra: Interface[%s] MTU change %u -> %u.",
                       ifp->name, if_tmp.mtu, ifp->mtu);

	  /* Must reset the interface (simulate down/up) when MTU changes. */
          ospf_if_reset(ifp);
	}
      return 0;
    }

  zebra_interface_if_set_value (zclient->ibuf, ifp);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_debug ("Zebra: Interface[%s] state change to up.", ifp->name);

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
    {
      if ((oi = rn->info) == NULL)
        continue;

      ospf_if_up (oi);
    }

  return 0;
}

static int
ospf_interface_state_down (int command, struct zclient *zclient,
                           zebra_size_t length)
{
  struct interface *ifp;
  struct ospf_interface *oi;
  struct route_node *node;

  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_debug ("Zebra: Interface[%s] state change to down.", ifp->name);

  for (node = route_top (IF_OIFS (ifp)); node; node = route_next (node))
    {
      if ((oi = node->info) == NULL)
        continue;
      ospf_if_down (oi);
    }

  return 0;
}

static int
ospf_interface_address_add (int command, struct zclient *zclient,
                            zebra_size_t length)
{
  struct connected *c;

  c = zebra_interface_address_read (command, zclient->ibuf);

  if (c == NULL)
    return 0;

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    {
      char buf[128];
      prefix2str(c->address, buf, sizeof(buf));
      zlog_debug("Zebra: interface %s address add %s", c->ifp->name, buf);
    }

  ospf_if_update (NULL, c->ifp);

#ifdef HAVE_SNMP
  ospf_snmp_if_update (c->ifp);
#endif /* HAVE_SNMP */

  return 0;
}

static int
ospf_interface_address_delete (int command, struct zclient *zclient,
                               zebra_size_t length)
{
  struct connected *c;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct route_node *rn;
  struct prefix p;

  c = zebra_interface_address_read (command, zclient->ibuf);

  if (c == NULL)
    return 0;

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    {
      char buf[128];
      prefix2str(c->address, buf, sizeof(buf));
      zlog_debug("Zebra: interface %s address delete %s", c->ifp->name, buf);
    }

  ifp = c->ifp;
  p = *c->address;
  p.prefixlen = IPV4_MAX_PREFIXLEN;

  rn = route_node_lookup (IF_OIFS (ifp), &p);
  if (!rn)
    {
      connected_free (c);
      return 0;
    }

  assert (rn->info);
  oi = rn->info;

  /* Call interface hook functions to clean up */
  ospf_if_free (oi);

#ifdef HAVE_SNMP
  ospf_snmp_if_update (c->ifp);
#endif /* HAVE_SNMP */

  connected_free (c);

  return 0;
}

void
ospf_zebra_add (struct prefix_ipv4 *p, struct ospf_route *or)
{
  u_char message;
  u_char distance;
  u_char flags;
  int psize;
  struct stream *s;
  struct ospf_path *path;
  struct listnode *node;

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      message = 0;
      flags = 0;

      /* OSPF pass nexthop and metric */
      SET_FLAG (message, ZAPI_MESSAGE_NEXTHOP);
      SET_FLAG (message, ZAPI_MESSAGE_METRIC);

      /* Distance value. */
      distance = ospf_distance_apply (p, or);
      if (distance)
        SET_FLAG (message, ZAPI_MESSAGE_DISTANCE);

      /* Make packet. */
      s = zclient->obuf;
      stream_reset (s);

      /* Put command, type, flags, message. */
      zclient_create_header (s, ZEBRA_IPV4_ROUTE_ADD);
      stream_putc (s, ZEBRA_ROUTE_OSPF);
      stream_putc (s, flags);
      stream_putc (s, message);
      stream_putw (s, SAFI_UNICAST);

      /* Put prefix information. */
      psize = PSIZE (p->prefixlen);
      stream_putc (s, p->prefixlen);
      stream_write (s, (u_char *) & p->prefix, psize);

      /* Nexthop count. */
      stream_putc (s, or->paths->count);

      /* Nexthop, ifindex, distance and metric information. */
      for (ALL_LIST_ELEMENTS_RO (or->paths, node, path))
        {
          if (path->nexthop.s_addr != INADDR_ANY &&
	      path->ifindex != 0)
            {
              stream_putc (s, ZEBRA_NEXTHOP_IPV4_IFINDEX);
              stream_put_in_addr (s, &path->nexthop);
	      stream_putl (s, path->ifindex);
            }
          else if (path->nexthop.s_addr != INADDR_ANY)
            {
              stream_putc (s, ZEBRA_NEXTHOP_IPV4);
              stream_put_in_addr (s, &path->nexthop);
            }
          else
            {
              stream_putc (s, ZEBRA_NEXTHOP_IFINDEX);
              if (path->ifindex)
                stream_putl (s, path->ifindex);
              else
                stream_putl (s, 0);
            }

          if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
            {
	      char buf[2][INET_ADDRSTRLEN];
	      zlog_debug("Zebra: Route add %s/%d nexthop %s",
			 inet_ntop(AF_INET, &p->prefix,
				   buf[0], sizeof(buf[0])),
			 p->prefixlen,
			 inet_ntop(AF_INET, &path->nexthop,
				   buf[1], sizeof(buf[1])));
            }
        }

      if (CHECK_FLAG (message, ZAPI_MESSAGE_DISTANCE))
        stream_putc (s, distance);
      if (CHECK_FLAG (message, ZAPI_MESSAGE_METRIC))
        {
          if (or->path_type == OSPF_PATH_TYPE1_EXTERNAL)
            stream_putl (s, or->cost + or->u.ext.type2_cost);
          else if (or->path_type == OSPF_PATH_TYPE2_EXTERNAL)
            stream_putl (s, or->u.ext.type2_cost);
          else
            stream_putl (s, or->cost);
        }

      stream_putw_at (s, 0, stream_get_endp (s));

      zclient_send_message(zclient);
    }
}

void
ospf_zebra_delete (struct prefix_ipv4 *p, struct ospf_route *or)
{
  u_char message;
  u_char distance;
  u_char flags;
  int psize;
  struct stream *s;
  struct ospf_path *path;
  struct listnode *node;

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      message = 0;
      flags = 0;
      /* Distance value. */
      distance = ospf_distance_apply (p, or);
      /* Make packet. */
      s = zclient->obuf;
      stream_reset (s);

      /* Put command, type, flags, message. */
      zclient_create_header (s, ZEBRA_IPV4_ROUTE_DELETE);
      stream_putc (s, ZEBRA_ROUTE_OSPF);
      stream_putc (s, flags);
      stream_putc (s, message);
      stream_putw (s, SAFI_UNICAST);

      /* Put prefix information. */
      psize = PSIZE (p->prefixlen);
      stream_putc (s, p->prefixlen);
      stream_write (s, (u_char *) & p->prefix, psize);

      /* Nexthop count. */
      stream_putc (s, or->paths->count);

      /* Nexthop, ifindex, distance and metric information. */
      for (ALL_LIST_ELEMENTS_RO (or->paths, node, path))
	{
	  if (path->nexthop.s_addr != INADDR_ANY &&
	      path->ifindex != 0)
	    {
	      stream_putc (s, ZEBRA_NEXTHOP_IPV4_IFINDEX);
	      stream_put_in_addr (s, &path->nexthop);
	      stream_putl (s, path->ifindex);
	    }
	  else if (path->nexthop.s_addr != INADDR_ANY)
	    {
	      stream_putc (s, ZEBRA_NEXTHOP_IPV4);
	      stream_put_in_addr (s, &path->nexthop);
	    }
	  else
	    {
	      stream_putc (s, ZEBRA_NEXTHOP_IFINDEX);
	      stream_putl (s, path->ifindex);
	    }

	  if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	    {
	      char buf[2][INET_ADDRSTRLEN];
	      zlog_debug("Zebra: Route delete %s/%d nexthop %s",
			 inet_ntop(AF_INET, &p->prefix,
				   buf[0], sizeof(buf[0])),
			 p->prefixlen,
			 inet_ntop(AF_INET, &path->nexthop,
				   buf[1], sizeof(buf[1])));
	    }
	}

      if (CHECK_FLAG (message, ZAPI_MESSAGE_DISTANCE))
	stream_putc (s, distance);
      if (CHECK_FLAG (message, ZAPI_MESSAGE_METRIC))
	{
	  if (or->path_type == OSPF_PATH_TYPE1_EXTERNAL)
	    stream_putl (s, or->cost + or->u.ext.type2_cost);
	  else if (or->path_type == OSPF_PATH_TYPE2_EXTERNAL)
	    stream_putl (s, or->u.ext.type2_cost);
	  else
	    stream_putl (s, or->cost);
	}

      stream_putw_at (s, 0, stream_get_endp (s));

      zclient_send_message(zclient);
    }
}

void
ospf_zebra_add_discard (struct prefix_ipv4 *p)
{
  struct zapi_ipv4 api;

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      api.type = ZEBRA_ROUTE_OSPF;
      api.flags = ZEBRA_FLAG_BLACKHOLE;
      api.message = 0;
      api.safi = SAFI_UNICAST;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 0;
      api.ifindex_num = 0;

      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_ADD, zclient, p, &api);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
        zlog_debug ("Zebra: Route add discard %s/%d",
                   inet_ntoa (p->prefix), p->prefixlen);
    }
}

void
ospf_zebra_delete_discard (struct prefix_ipv4 *p)
{
  struct zapi_ipv4 api;

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      api.type = ZEBRA_ROUTE_OSPF;
      api.flags = ZEBRA_FLAG_BLACKHOLE;
      api.message = 0;
      api.safi = SAFI_UNICAST;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 0;
      api.ifindex_num = 0;

      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, zclient, p, &api);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
        zlog_debug ("Zebra: Route delete discard %s/%d",
                   inet_ntoa (p->prefix), p->prefixlen);

    }
}

int
ospf_is_type_redistributed (int type)
{
  return (DEFAULT_ROUTE_TYPE (type)) ?
    zclient->default_information : zclient->redist[type];
}

int
ospf_redistribute_set (struct ospf *ospf, int type, int mtype, int mvalue)
{
  int force = 0;

  if (ospf_is_type_redistributed (type))
    {
      if (mtype != ospf->dmetric[type].type)
        {
          ospf->dmetric[type].type = mtype;
          force = LSA_REFRESH_FORCE;
        }
      if (mvalue != ospf->dmetric[type].value)
        {
          ospf->dmetric[type].value = mvalue;
          force = LSA_REFRESH_FORCE;
        }

      ospf_external_lsa_refresh_type (ospf, type, force);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
        zlog_debug ("Redistribute[%s]: Refresh  Type[%d], Metric[%d]",
                   ospf_redist_string(type),
                   metric_type (ospf, type), metric_value (ospf, type));

      return CMD_SUCCESS;
    }

  ospf->dmetric[type].type = mtype;
  ospf->dmetric[type].value = mvalue;

  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, type);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
    zlog_debug ("Redistribute[%s]: Start  Type[%d], Metric[%d]",
               ospf_redist_string(type),
               metric_type (ospf, type), metric_value (ospf, type));

  ospf_asbr_status_update (ospf, ++ospf->redistribute);

  return CMD_SUCCESS;
}

int
ospf_redistribute_unset (struct ospf *ospf, int type)
{
  if (type == zclient->redist_default)
    return CMD_SUCCESS;

  if (!ospf_is_type_redistributed (type))
    return CMD_SUCCESS;

  zclient_redistribute (ZEBRA_REDISTRIBUTE_DELETE, zclient, type);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
    zlog_debug ("Redistribute[%s]: Stop",
               ospf_redist_string(type));

  ospf->dmetric[type].type = -1;
  ospf->dmetric[type].value = -1;

  /* Remove the routes from OSPF table. */
  ospf_redistribute_withdraw (ospf, type);

  ospf_asbr_status_update (ospf, --ospf->redistribute);

  return CMD_SUCCESS;
}

int
ospf_redistribute_default_set (struct ospf *ospf, int originate,
                               int mtype, int mvalue)
{
  ospf->default_originate = originate;
  ospf->dmetric[DEFAULT_ROUTE].type = mtype;
  ospf->dmetric[DEFAULT_ROUTE].value = mvalue;

  if (ospf_is_type_redistributed (DEFAULT_ROUTE))
    {
      /* if ospf->default_originate changes value, is calling
	 ospf_external_lsa_refresh_default sufficient to implement
	 the change? */
      ospf_external_lsa_refresh_default (ospf);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
        zlog_debug ("Redistribute[%s]: Refresh  Type[%d], Metric[%d]",
                   ospf_redist_string(DEFAULT_ROUTE),
                   metric_type (ospf, DEFAULT_ROUTE),
                   metric_value (ospf, DEFAULT_ROUTE));
      return CMD_SUCCESS;
    }

  zclient_redistribute_default (ZEBRA_REDISTRIBUTE_DEFAULT_ADD, zclient);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
    zlog_debug ("Redistribute[DEFAULT]: Start  Type[%d], Metric[%d]",
               metric_type (ospf, DEFAULT_ROUTE),
               metric_value (ospf, DEFAULT_ROUTE));

  if (ospf->router_id.s_addr == 0)
    ospf->external_origin |= (1 << DEFAULT_ROUTE);
  else
    thread_add_timer (master, ospf_default_originate_timer, ospf, 1);

  ospf_asbr_status_update (ospf, ++ospf->redistribute);

  return CMD_SUCCESS;
}

int
ospf_redistribute_default_unset (struct ospf *ospf)
{
  if (!ospf_is_type_redistributed (DEFAULT_ROUTE))
    return CMD_SUCCESS;

  ospf->default_originate = DEFAULT_ORIGINATE_NONE;
  ospf->dmetric[DEFAULT_ROUTE].type = -1;
  ospf->dmetric[DEFAULT_ROUTE].value = -1;

  zclient_redistribute_default (ZEBRA_REDISTRIBUTE_DEFAULT_DELETE, zclient);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
    zlog_debug ("Redistribute[DEFAULT]: Stop");

  ospf_asbr_status_update (ospf, --ospf->redistribute);

  return CMD_SUCCESS;
}

static int
ospf_external_lsa_originate_check (struct ospf *ospf,
                                   struct external_info *ei)
{
  /* If prefix is multicast, then do not originate LSA. */
  if (IN_MULTICAST (htonl (ei->p.prefix.s_addr)))
    {
      zlog_info ("LSA[Type5:%s]: Not originate AS-external-LSA, "
                 "Prefix belongs multicast", inet_ntoa (ei->p.prefix));
      return 0;
    }

  /* Take care of default-originate. */
  if (is_prefix_default (&ei->p))
    if (ospf->default_originate == DEFAULT_ORIGINATE_NONE)
      {
        zlog_info ("LSA[Type5:0.0.0.0]: Not originate AS-external-LSA "
                   "for default");
        return 0;
      }

  return 1;
}

/* If connected prefix is OSPF enable interface, then do not announce. */
int
ospf_distribute_check_connected (struct ospf *ospf, struct external_info *ei)
{
  struct listnode *node;
  struct ospf_interface *oi;


  for (ALL_LIST_ELEMENTS_RO (ospf->oiflist, node, oi))
      if (prefix_match (oi->address, (struct prefix *) &ei->p))
          return 0;
  return 1;
}

/* return 1 if external LSA must be originated, 0 otherwise */
int
ospf_redistribute_check (struct ospf *ospf,
                         struct external_info *ei, int *changed)
{
  struct prefix_ipv4 *p = &ei->p;
  u_char type = is_prefix_default (&ei->p) ? DEFAULT_ROUTE : ei->type;

  if (changed)
    *changed = 0;

  if (!ospf_external_lsa_originate_check (ospf, ei))
    return 0;

  /* Take care connected route. */
  if (type == ZEBRA_ROUTE_CONNECT &&
      !ospf_distribute_check_connected (ospf, ei))
    return 0;

  if (!DEFAULT_ROUTE_TYPE (type) && DISTRIBUTE_NAME (ospf, type))
    /* distirbute-list exists, but access-list may not? */
    if (DISTRIBUTE_LIST (ospf, type))
      if (access_list_apply (DISTRIBUTE_LIST (ospf, type), p) == FILTER_DENY)
        {
          if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
            zlog_debug ("Redistribute[%s]: %s/%d filtered by ditribute-list.",
                       ospf_redist_string(type),
                       inet_ntoa (p->prefix), p->prefixlen);
          return 0;
        }

  /* apply route-map if needed */
  if (ROUTEMAP_NAME (ospf, type))
    {
      int ret;
      struct route_map_set_values save_values;

      save_values = ei->route_map_set;
      ospf_reset_route_map_set_values (&ei->route_map_set);

      ret = route_map_apply (ROUTEMAP (ospf, type), (struct prefix *) p,
                             RMAP_OSPF, ei);

      if (ret == RMAP_DENYMATCH)
        {
          ei->route_map_set = save_values;
          if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
            zlog_debug ("Redistribute[%s]: %s/%d filtered by route-map.",
                       ospf_redist_string(type),
                       inet_ntoa (p->prefix), p->prefixlen);
          return 0;
        }

      /* check if 'route-map set' changed something */
      if (changed)
        *changed = !ospf_route_map_set_compare (&ei->route_map_set,
                                                &save_values);
    }

  return 1;
}

/* OSPF route-map set for redistribution */
void
ospf_routemap_set (struct ospf *ospf, int type, const char *name)
{
  if (ROUTEMAP_NAME (ospf, type))
    free (ROUTEMAP_NAME (ospf, type));

  ROUTEMAP_NAME (ospf, type) = strdup (name);
  ROUTEMAP (ospf, type) = route_map_lookup_by_name (name);
}

void
ospf_routemap_unset (struct ospf *ospf, int type)
{
  if (ROUTEMAP_NAME (ospf, type))
    free (ROUTEMAP_NAME (ospf, type));

  ROUTEMAP_NAME (ospf, type) = NULL;
  ROUTEMAP (ospf, type) = NULL;
}

/* Zebra route add and delete treatment. */
static int
ospf_zebra_read_ipv4 (int command, struct zclient *zclient,
                      zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv4 api;
  unsigned long ifindex;
  struct in_addr nexthop;
  struct prefix_ipv4 p;
  struct external_info *ei;
  struct ospf *ospf;

  s = zclient->ibuf;
  ifindex = 0;
  nexthop.s_addr = 0;

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  if (IPV4_NET127(ntohl(p.prefix.s_addr)))
    return 0;

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      nexthop.s_addr = stream_get_ipv4 (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      /* XXX assert(api.ifindex_num == 1); */
      ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);

  ospf = ospf_lookup ();
  if (ospf == NULL)
    return 0;

  if (command == ZEBRA_IPV4_ROUTE_ADD)
    {
      /* XXX|HACK|TODO|FIXME:
       * Maybe we should ignore reject/blackhole routes? Testing shows that
       * there is no problems though and this is only way to "summarize"
       * routes in ASBR at the moment. Maybe we need just a better generalised
       * solution for these types?
       *
       * if ( CHECK_FLAG (api.flags, ZEBRA_FLAG_BLACKHOLE)
       *     || CHECK_FLAG (api.flags, ZEBRA_FLAG_REJECT))
       * return 0;
       */

      ei = ospf_external_info_add (api.type, p, ifindex, nexthop);

      if (ospf->router_id.s_addr == 0)
        /* Set flags to generate AS-external-LSA originate event
           for each redistributed protocols later. */
        ospf->external_origin |= (1 << api.type);
      else
        {
          if (ei)
            {
              if (is_prefix_default (&p))
                ospf_external_lsa_refresh_default (ospf);
              else
                {
                  struct ospf_lsa *current;

                  current = ospf_external_info_find_lsa (ospf, &ei->p);
                  if (!current)
                    ospf_external_lsa_originate (ospf, ei);
                  else if (IS_LSA_MAXAGE (current))
                    ospf_external_lsa_refresh (ospf, current,
                                               ei, LSA_REFRESH_FORCE);
                  else
                    zlog_warn ("ospf_zebra_read_ipv4() : %s already exists",
                               inet_ntoa (p.prefix));
                }
            }
        }
    }
  else                          /* if (command == ZEBRA_IPV4_ROUTE_DELETE) */
    {
      ospf_external_info_delete (api.type, p);
      if (is_prefix_default (&p))
        ospf_external_lsa_refresh_default (ospf);
      else
        ospf_external_lsa_flush (ospf, api.type, &p, ifindex /*, nexthop */);
    }

  return 0;
}


int
ospf_distribute_list_out_set (struct ospf *ospf, int type, const char *name)
{
  /* Lookup access-list for distribute-list. */
  DISTRIBUTE_LIST (ospf, type) = access_list_lookup (AFI_IP, name);

  /* Clear previous distribute-name. */
  if (DISTRIBUTE_NAME (ospf, type))
    free (DISTRIBUTE_NAME (ospf, type));

  /* Set distribute-name. */
  DISTRIBUTE_NAME (ospf, type) = strdup (name);

  /* If access-list have been set, schedule update timer. */
  if (DISTRIBUTE_LIST (ospf, type))
    ospf_distribute_list_update (ospf, type);

  return CMD_SUCCESS;
}

int
ospf_distribute_list_out_unset (struct ospf *ospf, int type, const char *name)
{
  /* Schedule update timer. */
  if (DISTRIBUTE_LIST (ospf, type))
    ospf_distribute_list_update (ospf, type);

  /* Unset distribute-list. */
  DISTRIBUTE_LIST (ospf, type) = NULL;

  /* Clear distribute-name. */
  if (DISTRIBUTE_NAME (ospf, type))
    free (DISTRIBUTE_NAME (ospf, type));

  DISTRIBUTE_NAME (ospf, type) = NULL;

  return CMD_SUCCESS;
}

/* distribute-list update timer. */
static int
ospf_distribute_list_update_timer (struct thread *thread)
{
  struct route_node *rn;
  struct external_info *ei;
  struct route_table *rt;
  struct ospf_lsa *lsa;
  int type, default_refresh = 0;
  struct ospf *ospf;

  ospf = ospf_lookup ();
  if (ospf == NULL)
    return 0;

  ospf->t_distribute_update = NULL;

  zlog_info ("Zebra[Redistribute]: distribute-list update timer fired!");

  /* foreach all external info. */
  for (type = 0; type <= ZEBRA_ROUTE_MAX; type++)
    {
      rt = EXTERNAL_INFO (type);
      if (!rt)
	continue;
      for (rn = route_top (rt); rn; rn = route_next (rn))
	if ((ei = rn->info) != NULL)
	  {
	    if (is_prefix_default (&ei->p))
	      default_refresh = 1;
	    else if ((lsa = ospf_external_info_find_lsa (ospf, &ei->p)))
	      ospf_external_lsa_refresh (ospf, lsa, ei, LSA_REFRESH_IF_CHANGED);
	    else
	      ospf_external_lsa_originate (ospf, ei);
	  }
    }
  if (default_refresh)
    ospf_external_lsa_refresh_default (ospf);
  return 0;
}

/* Update distribute-list and set timer to apply access-list. */
void
ospf_distribute_list_update (struct ospf *ospf, uintptr_t type)
{
  struct route_table *rt;

  /* External info does not exist. */
  if (!(rt = EXTERNAL_INFO (type)))
    return;

  /* If exists previously invoked thread, then let it continue. */
  if (ospf->t_distribute_update)
    return;

  /* Set timer. */
  ospf->t_distribute_update =
    thread_add_timer_msec (master, ospf_distribute_list_update_timer,
                      (void *) type, ospf->min_ls_interval);
}

/* If access-list is updated, apply some check. */
static void
ospf_filter_update (struct access_list *access)
{
  struct ospf *ospf;
  int type;
  int abr_inv = 0;
  struct ospf_area *area;
  struct listnode *node;

  /* If OSPF instatnce does not exist, return right now. */
  ospf = ospf_lookup ();
  if (ospf == NULL)
    return;

  /* Update distribute-list, and apply filter. */
  for (type = 0; type <= ZEBRA_ROUTE_MAX; type++)
    {
      if (ROUTEMAP (ospf, type) != NULL)
        {
          /* if route-map is not NULL it may be using this access list */
          ospf_distribute_list_update (ospf, type);
          continue;
        }

      /* There is place for route-map for default-information (ZEBRA_ROUTE_MAX),
       * but no distribute list. */
      if (type == ZEBRA_ROUTE_MAX)
	break;

      if (DISTRIBUTE_NAME (ospf, type))
        {
          /* Keep old access-list for distribute-list. */
          struct access_list *old = DISTRIBUTE_LIST (ospf, type);

          /* Update access-list for distribute-list. */
          DISTRIBUTE_LIST (ospf, type) =
            access_list_lookup (AFI_IP, DISTRIBUTE_NAME (ospf, type));

          /* No update for this distribute type. */
          if (old == NULL && DISTRIBUTE_LIST (ospf, type) == NULL)
            continue;

          /* Schedule distribute-list update timer. */
          if (DISTRIBUTE_LIST (ospf, type) == NULL ||
              strcmp (DISTRIBUTE_NAME (ospf, type), access->name) == 0)
            ospf_distribute_list_update (ospf, type);
        }
    }

  /* Update Area access-list. */
  for (ALL_LIST_ELEMENTS_RO (ospf->areas, node, area))
    {
      if (EXPORT_NAME (area))
        {
          EXPORT_LIST (area) = NULL;
          abr_inv++;
        }

      if (IMPORT_NAME (area))
        {
          IMPORT_LIST (area) = NULL;
          abr_inv++;
        }
    }

  /* Schedule ABR tasks -- this will be changed -- takada. */
  if (IS_OSPF_ABR (ospf) && abr_inv)
    ospf_schedule_abr_task (ospf);
}

/* If prefix-list is updated, do some updates. */
void
ospf_prefix_list_update (struct prefix_list *plist)
{
  struct ospf *ospf;
  int type;
  int abr_inv = 0;
  struct ospf_area *area;
  struct listnode *node;

  /* If OSPF instatnce does not exist, return right now. */
  ospf = ospf_lookup ();
  if (ospf == NULL)
    return;

  /* Update all route-maps which are used as redistribution filters.
   * They might use prefix-list.
   */
  for (type = 0; type <= ZEBRA_ROUTE_MAX; type++)
    {
      if (ROUTEMAP (ospf, type) != NULL)
        {
          /* If route-map is not NULL it may be using this prefix list */
          ospf_distribute_list_update (ospf, type);
          continue;
        }
    }

  /* Update area filter-lists. */
  for (ALL_LIST_ELEMENTS_RO (ospf->areas, node, area))
    {
      /* Update filter-list in. */
      if (PREFIX_NAME_IN (area))
        if (strcmp (PREFIX_NAME_IN (area), plist->name) == 0)
          {
            PREFIX_LIST_IN (area) =
              prefix_list_lookup (AFI_IP, PREFIX_NAME_IN (area));
            abr_inv++;
          }

      /* Update filter-list out. */
      if (PREFIX_NAME_OUT (area))
        if (strcmp (PREFIX_NAME_OUT (area), plist->name) == 0)
          {
            PREFIX_LIST_IN (area) =
              prefix_list_lookup (AFI_IP, PREFIX_NAME_OUT (area));
            abr_inv++;
          }
    }

  /* Schedule ABR task. */
  if (IS_OSPF_ABR (ospf) && abr_inv)
    ospf_schedule_abr_task (ospf);
}

static struct ospf_distance *
ospf_distance_new (void)
{
  return XCALLOC (MTYPE_OSPF_DISTANCE, sizeof (struct ospf_distance));
}

static void
ospf_distance_free (struct ospf_distance *odistance)
{
  XFREE (MTYPE_OSPF_DISTANCE, odistance);
}

int
ospf_distance_set (struct vty *vty, struct ospf *ospf,
                   const char *distance_str,
                   const char *ip_str,
                   const char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct route_node *rn;
  struct ospf_distance *odistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  /* Get OSPF distance node. */
  rn = route_node_get (ospf->distance_table, (struct prefix *) &p);
  if (rn->info)
    {
      odistance = rn->info;
      route_unlock_node (rn);
    }
  else
    {
      odistance = ospf_distance_new ();
      rn->info = odistance;
    }

  /* Set distance value. */
  odistance->distance = distance;

  /* Reset access-list configuration. */
  if (odistance->access_list)
    {
      free (odistance->access_list);
      odistance->access_list = NULL;
    }
  if (access_list_str)
    odistance->access_list = strdup (access_list_str);

  return CMD_SUCCESS;
}

int
ospf_distance_unset (struct vty *vty, struct ospf *ospf,
                     const char *distance_str,
                     const char *ip_str, char
                     const *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct ospf_distance *odistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_lookup (ospf->distance_table, (struct prefix *) &p);
  if (!rn)
    {
      vty_out (vty, "Can't find specified prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  odistance = rn->info;

  if (odistance->access_list)
    free (odistance->access_list);
  ospf_distance_free (odistance);

  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

void
ospf_distance_reset (struct ospf *ospf)
{
  struct route_node *rn;
  struct ospf_distance *odistance;

  for (rn = route_top (ospf->distance_table); rn; rn = route_next (rn))
    if ((odistance = rn->info) != NULL)
      {
        if (odistance->access_list)
          free (odistance->access_list);
        ospf_distance_free (odistance);
        rn->info = NULL;
        route_unlock_node (rn);
      }
}

u_char
ospf_distance_apply (struct prefix_ipv4 *p, struct ospf_route *or)
{
  struct ospf *ospf;

  ospf = ospf_lookup ();
  if (ospf == NULL)
    return 0;

  if (ospf->distance_intra)
    if (or->path_type == OSPF_PATH_INTRA_AREA)
      return ospf->distance_intra;

  if (ospf->distance_inter)
    if (or->path_type == OSPF_PATH_INTER_AREA)
      return ospf->distance_inter;

  if (ospf->distance_external)
    if (or->path_type == OSPF_PATH_TYPE1_EXTERNAL
        || or->path_type == OSPF_PATH_TYPE2_EXTERNAL)
      return ospf->distance_external;

  if (ospf->distance_all)
    return ospf->distance_all;

  return 0;
}

static int
_read_non_block(int nbytes)
{
  int rval;

  while (nbytes) {
eretry:
    rval = stream_read_try (zclient->ibuf, zclient->sock, nbytes);
	if (rval == -2)
		goto eretry;
	if (rval == -1) {
	  zlog_err ("%s: Failed to read response from Zebra!", __func__);
	  return nbytes;
	}
	nbytes -= rval;
  }
  return 0;
}

int
ospf_zebra_lookup_read (u_int32_t addr,  struct ospf_route *route)
{
  struct stream *s;
  uint16_t length;
  u_char marker;
  u_char version;
  uint16_t command;
  struct in_addr raddr;
  u_char nexthop_num;
  u_char i;
  u_char type;
  struct ospf_path *new;

  s = zclient->ibuf;
  stream_reset (s);
  /* read header length field */
  _read_non_block(2);

  length = stream_getw (s) - 2;
  if (length < 13)  /* 1 + 1 + 2 + 4 + 4 + 1 */
    {
      zlog_err ("%s: Uncomplete message from zebra (%u)!", __func__, length);
	  return 0;
    }

  /* Already read 2 bytes, scan until the end */
  _read_non_block(length);

  marker = stream_getc (s);
  version = stream_getc (s);

  if (version != ZSERV_VERSION || marker != ZEBRA_HEADER_MARKER)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, zclient->sock, marker, version);
      return 0;
    }

  command = stream_getw (s);
  if (command != ZEBRA_IPV4_NEXTHOP_LOOKUP)
	{
	  zlog_err ("%s: Unexpected Zebra command reply, %s instead of %s",
			    __func__, zserv_command_string(command),
				zserv_command_string(ZEBRA_IPV4_NEXTHOP_LOOKUP));
	  return 0;
	}
  raddr.s_addr = stream_get_ipv4 (s);
  if (raddr.s_addr != addr)
	{
	  char addr_str[INET_ADDRSTRLEN], raddr_str[INET_ADDRSTRLEN];
	  inet_ntop (AF_INET, &raddr, raddr_str, sizeof(raddr_str));
	  raddr.s_addr = addr;
	  inet_ntop (AF_INET, &raddr, addr_str, sizeof(addr_str));
	  zlog_err ("%s: Unexpected Zebra lookup key, %s instead of %s",
			    __func__, addr_str, raddr_str);
	  return 0;
	}

  route->cost = stream_getl (s);
  nexthop_num = stream_getc (s);
  zlog_debug("%s: Found %d nexthops with metric %d",
		     __func__, nexthop_num, route->cost);
  for (list_delete_all_node (route->paths), i = 0;
		 i < nexthop_num && length; ++i) {
	type = stream_getc (s);
	--length;
	new = ospf_path_new();
	new->adv_router = raddr;
	switch (type)
	  {
	  case ZEBRA_NEXTHOP_IPV4:
	length -= 4;
	if (length >= 0) new->nexthop.s_addr = stream_get_ipv4 (s);
	break;
	  case ZEBRA_NEXTHOP_IPV4_IFINDEX:
	length -= 8;
	if (length < 0) break;
	new->nexthop.s_addr = stream_get_ipv4 (s);
	new->ifindex = stream_getl (s);
	break;
	  case ZEBRA_NEXTHOP_IFINDEX:
	  case ZEBRA_NEXTHOP_IFNAME:
	length -= 4;
	if (length >= 0) new->ifindex = stream_getl (s);
	break;
	  default:
			/* never reached */
	zlog_err("%s: Unexpected nexthop type! %u",
			__func__, type);
	ospf_path_free (new);
	break;
	  }
	if (length >= 0)
        listnode_add (route->paths, new);
	else
		ospf_path_free (new);
  }
  if (i < nexthop_num || length < 0)
	  zlog_err ("%s: Couldn't read all nexthops! Stopped after %u",
			  __func__, i);
  return nexthop_num;
}

int
ospf_zebra_lookup_query (u_int32_t addr)
{
  int ret;
  struct stream *s;

  if (zclient->sock < 0)
    return 0;

  s = zclient->obuf;
  stream_reset (s);
  zclient_create_header (s, ZEBRA_IPV4_NEXTHOP_LOOKUP);
  stream_put_ipv4 (s, addr);

  stream_putw_at (s, 0, stream_get_endp (s));

  ret = writen (zclient->sock, s->data, stream_get_endp (s));
  if (ret < 0)
    {
      zlog_err ("can't write to zclient->sock");
      close (zclient->sock);
      zclient->sock = -1;
      return 1;
    }
  if (ret == 0)
    {
      zlog_err ("zclient->sock connection closed");
      close (zclient->sock);
      zclient->sock = -1;
      return 1;
    }

  return 0;
}

void
ospf_zebra_init ()
{
  /* Allocate zebra structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_OSPF);
  zclient->router_id_update = ospf_router_id_update_zebra;
  zclient->interface_add = ospf_interface_add;
  zclient->interface_delete = ospf_interface_delete;
  zclient->interface_up = ospf_interface_state_up;
  zclient->interface_down = ospf_interface_state_down;
  zclient->interface_address_add = ospf_interface_address_add;
  zclient->interface_address_delete = ospf_interface_address_delete;
  zclient->ipv4_route_add = ospf_zebra_read_ipv4;
  zclient->ipv4_route_delete = ospf_zebra_read_ipv4;

  access_list_add_hook (ospf_filter_update);
  access_list_delete_hook (ospf_filter_update);
  prefix_list_add_hook (ospf_prefix_list_update);
  prefix_list_delete_hook (ospf_prefix_list_update);
}
