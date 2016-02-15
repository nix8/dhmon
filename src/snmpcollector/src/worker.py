#!/usr/bin/env python2
import collections
import logging
import re

import actions
import config
import multiprocessing
import snmp
import stage


# How many sub-workers to spawn to enumerate VLAN OIDs
VLAN_MAP_POOL = 2


def _poll(data):
  """Helper function that is run in a multiprocessing pool.

  This is to make VLAN context polls much faster.
  Some contexts doesn't exist and will just time out, which takes
  a loong time. So we run them in parallel.
  """
  target, vlan, oids = data
  errors = 0
  timeouts = 0
  results = {}
  for oid in oids:
    logging.debug('Collecting %s on %s @ %s', oid, target.host, vlan)
    if not oid.startswith('.1'):
      logging.warning(
          'OID %s does not start with .1, please verify configuration', oid)
      continue
    try:
      results.update(
          {(k, vlan): v for k, v in target.walk(oid, vlan).iteritems()})
    except snmp.TimeoutError, e:
      timeouts += 1
      if vlan:
        logging.debug(
            'Timeout, is switch configured for VLAN SNMP context? %s', e)
      else:
        logging.debug('Timeout, slow switch? %s', e)
    except snmp.Error, e:
      errors += 1
      logging.warning('SNMP error for OID %s@%s: %s', oid, vlan, str(e))
  return results, errors, timeouts


class Worker(object):

  def __init__(self):
    super(Worker, self).__init__()
    self.model_oid_cache = {}
    self.model_oid_cache_incarnation = 0
    self.pool = multiprocessing.Pool(processes=VLAN_MAP_POOL)

  def gather_oids(self, target, model):
    if config.incarnation() != self.model_oid_cache_incarnation:
      self.model_oid_cache_incarnation = config.incarnation()
      self.model_oid_cache = {}

    cache_key = (target.layer, model)
    if cache_key in self.model_oid_cache:
      return self.model_oid_cache[cache_key]

    oids = set()
    vlan_aware_oids = set()
    for collection_name, collection in config.get('collection').iteritems():
      for regexp in collection['models']:
        layers = collection.get('layers', None)
        if layers and target.layer not in layers:
          continue
        if 'oids' in collection and re.match(regexp, model):
          logging.debug(
              'Model %s matches collection %s', model, collection_name)
          # VLAN aware collections are run against every VLAN.
          # We don't want to run all the other OIDs (there can be a *lot* of
          # VLANs).
          vlan_aware = collection.get('vlan_aware', False)
          if vlan_aware:
            vlan_aware_oids.update(set(collection['oids']))
          else:
            oids.update(set(collection['oids']))
    self.model_oid_cache[cache_key] = (list(oids), list(vlan_aware_oids))
    return self.model_oid_cache[cache_key]

  def process_overrides(self, results):
    overrides = config.get('worker', 'override')
    if not overrides:
      return results
    overridden_oids = set(overrides.keys())

    overriden_results = results
    for oid, result in results.iteritems():
      root = '.'.join(oid[0].split('.')[:-1])
      if root in overridden_oids:
        overriden_results[oid] = snmp.ResultTuple( result.value, overrides[root])
    return overriden_results

  def do_snmp_walk(self, run, target):
    results, errors, timeouts = self._walk(target)
    results = results if results else {}
    logging.debug('Done SNMP poll (%d objects) for "%s"',
        len(results.keys()), target.host)
    yield actions.Result(target, results, actions.Statistics(timeouts, errors))

  def _walk(self, target):
    try:
      model = target.model()
    except snmp.TimeoutError, e:
      logging.exception('Could not determine model of %s:', target.host)
      return None, 0, 1
    except snmp.Error, e:
      logging.exception('Could not determine model of %s:', target.host)
      return None, 1, 0
    if not model:
      logging.error('Could not determine model of %s')
      return None, 1, 0

    logging.debug('Object %s is model %s', target.host, model)
    global_oids, vlan_oids = self.gather_oids(target, model)

    timeouts = 0
    errors = 0

    # 'None' is global (no VLAN aware)
    vlans = set([None])
    try:
      if vlan_oids:
        vlans.update(target.vlans())
    except snmp.Error, e:
      errors += 1
      logging.warning('Could not list VLANs: %s', str(e))

    to_poll = []
    for vlan in list(vlans):
      oids = vlan_oids if vlan else global_oids
      to_poll.append((target, vlan, oids))

    results = {}
    for part_results, part_errors, part_timeouts in self.pool.imap(
        _poll, to_poll):
      results.update(self.process_overrides(part_results))
      errors += part_errors
      timeouts += part_timeouts
    return results, errors, timeouts


if __name__ == '__main__':
  worker = stage.Stage(Worker())
  worker.listen(actions.SnmpWalk)
  worker.run()
