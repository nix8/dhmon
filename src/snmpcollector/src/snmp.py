import collections
import logging
import os
import sys


_NETSNMP_CACHE = None

ResultTuple = collections.namedtuple('ResultTuple', ['value', 'type'])


class Error(Exception):
  """Base error class for this module."""


class TimeoutError(Error):
  """Timeout talking to the device."""


class NoModelOid(Error):
  """Could not locate a model for the switch."""


class SnmpError(Error):
  """A SNMP error occurred."""


class SnmpTarget(object):

  def __init__(self, host, ip, timestamp, layer, version, community=None,
      user=None, auth_proto=None, auth=None, priv_proto=None, priv=None,
      sec_level=None,
      port=161):
    self._full_host = "%s:%s" % (ip, port)
    self._max_size = 256
    self.host=host
    self.ip=ip
    self.timestamp=timestamp
    self.layer=layer
    self.version=version
    self.community=community
    self.user=user
    self.auth_proto=auth_proto
    self.auth=auth
    self.priv_proto=priv_proto
    self.priv=priv
    self.sec_level=sec_level
    self.netsnmp = None

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return False
    return (
        self.host == other.host and self.ip == other.ip and
        self.timestamp == other.timestamp and self.layer == other.layer and
        self.version == other.version and self.community == other.community and
        self.user == other.user and self.auth_proto == other.auth_proto and
        self.auth == other.auth and self.priv_proto == other.priv_proto and
        self.priv == other.priv and self.sec_level == other.sec_level)

  def _snmp_session(self, vlan=None, timeout=2000000, retries=3):
    # Since pickle will import this module we do not want to drag netsnmp into
    # this on every load. Load it when we need it.
    global _NETSNMP_CACHE
    first_load = False
    if _NETSNMP_CACHE is None:
      first_load = True
      import netsnmp
      _NETSNMP_CACHE = netsnmp
    else:
      netsnmp = _NETSNMP_CACHE

    if sys.version_info[0] == 3:
      from fastsnmp import snmp_poller 
      return ""

    if first_load:
      # Loading MIBs can be very noisy, so we close stderr
      # Ideally we would just call netsnmp_register_loghandler but that isn't
      # exported :-(
      stderr = os.dup(sys.stderr.fileno())
      null = os.open(os.devnull, os.O_RDWR)
      os.close(sys.stderr.fileno())
      os.dup2(null, sys.stderr.fileno())
      os.close(null)

    if self.version == 3:
      context = ('vlan-%s' % vlan) if vlan else ''
      session = netsnmp.Session(Version=3, DestHost=self._full_host,
        SecName=self.user, SecLevel=self.sec_level, Context=context,
        AuthProto=self.auth_proto, AuthPass=self.auth,
        PrivProto=self.priv_proto, PrivPass=self.priv,
        UseNumeric=1, Timeout=timeout, Retries=retries), netsnmp
    else:
      community = ('%s@%s' % (self.community, vlan)) if vlan else self.community
      session = netsnmp.Session(Version=self.version, DestHost=self._full_host,
          Community=community, UseNumeric=1, Timeout=timeout,
          Retries=retries), netsnmp

    if first_load:
      # Restore stderr
      os.dup2(stderr, sys.stderr.fileno())
      os.close(stderr)
    return session

  def walk_fastsnmp(self, oids, vlan=None):
    ret = {}

    from fastsnmp import snmp_poller
  
    new_oids = {}
    for oid in oids:
      m_oid = oid.rstrip('1234567890')
      if new_oids.get( m_oid, None ) == None:
         new_oids[m_oid] = ({})
      new_oids[m_oid][oid] = 0

    for oid_base in new_oids:
      t_oids = ([]) 
      for oid in new_oids[oid_base]:
         t_oids.append(oid)
      snmp_data = snmp_poller.poller((self.ip,), tuple([t_oids]), self.community)
      for data in snmp_data:
        snmp_host, snmp_oid, snmp_idx, snmp_value, snmp_type = data
        ret[ ".%s.%s" %(snmp_oid, snmp_idx) ] = ResultTuple(snmp_value, snmp_type)

    return ret


  def walk(self, oid, vlan=None):
    ret = {}
    nextoid = oid
    offset = 0

    if sys.version_info[0] == 3:
      from fastsnmp import snmp_poller
      snmp_data =[x for x in snmp_poller.poller((self.ip,), ([oid[1:]],), self.community) ]
     
      for data in snmp_data:
          snmp_host, snmp_oid, snmp_idx, snmp_value, snmp_type = data
          ret[ ".%s.%s" %(snmp_oid, snmp_idx) ] = ResultTuple(snmp_value, snmp_type)
      return ret

    sess, netsnmp = self._snmp_session(vlan)
    # Abort the walk when it exits the OID tree we are interested in
    while nextoid.startswith(oid):
      if offset == 0:
         var_list = netsnmp.VarList(netsnmp.Varbind(nextoid))
      else:
         var_list = netsnmp.VarList(netsnmp.Varbind(nextoid, offset))
      sess.getbulk(nonrepeaters=0, maxrepetitions=self._max_size, varlist=var_list)

      # WORKAROUND FOR NEXUS BUG (2014-11-24)
      # Indy told blueCmd that Nexus silently drops the SNMP response
      # if the packet is fragmented. Try with large size first, but drop down
      # to smaller one.
      if sess.ErrorStr == 'Timeout':
        if self._max_size == 1:
          raise TimeoutError(
              'Timeout getting %s from %s' % (nextoid, self.host))
        self._max_size = int(self._max_size / 16)
        continue
      if sess.ErrorStr != '':
        raise SnmpError('SNMP error while walking host %s: %s' % (
          self.host, sess.ErrorStr))

      for result in var_list:
        currentoid = '%s.%s' % (result.tag, int(result.iid))
        # We don't want to save extra oids that the bulk walk might have
        # contained.
        if not currentoid.startswith(oid):
          break
        ret[currentoid] = ResultTuple(result.val, result.type)
      # Continue bulk walk
      offset = int(var_list[-1].iid)
      if offset == 0:
         break
      nextoid = var_list[-1].tag
    return ret

  def get(self, oid):

    if sys.version_info[0] == 3:
      from fastsnmp import snmp_poller
      snmp_data =[x for x in snmp_poller.poller((self.ip,), ([oid[1:]],), self.community) ]
      if len(snmp_data) == 0:
         return { oid: ResultTuple("", "OCTETSTR") }
      return { oid: ResultTuple(snmp_data[0][3], snmp_data[0][4]) }



    sess, netsnmp = self._snmp_session(timeout=5000000, retries=2)

    var = netsnmp.Varbind(oid)
    var_list = netsnmp.VarList(var)
    sess.get(var_list)
    if sess.ErrorStr != '':
      if sess.ErrorStr == 'Timeout':
        raise TimeoutError('Timeout getting %s from %s' % (oid, self.host))
      raise SnmpError('SNMP error while talking to host %s: %s' % (
        self.host, sess.ErrorStr))


    return {var.tag: ResultTuple(var.val, var.type)}

  def model(self):
    model_oids = [
        '.1.3.6.1.2.1.47.1.1.1.1.13.1',     # Normal switches
        '.1.3.6.1.2.1.47.1.1.1.1.13.1001',  # Stacked switches
        '.1.3.6.1.2.1.47.1.1.1.1.13.10',    # Nexus
        '.1.3.6.1.2.1.1.1.0',               # Other appliances (sysDescr)
        '.1.3.6.1.2.1.1.1',                 # Other appliances (sysDescr)
    ]
    for oid in model_oids:
      model = self.get(oid)
      if not model:
        continue
      if sys.version_info[0] < 3:
        value = model.values().pop().value
      else:
        value = list(model.values()).pop().value
      if value:
        return value
    raise NoModelOid('No model OID contained a model')

  def vlans(self):
    try:
      oids = self.walk('.1.3.6.1.4.1.9.9.46.1.3.1.1.2').keys()
      vlans = {int(x.split('.')[-1]) for x in oids}
      return vlans
    except ValueError as e:
      logging.info('ValueError while parsing VLAN for %s: %s', self.host, e)
      return []
