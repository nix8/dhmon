import argparse
import logging
import logging.handlers
import os
import pickle
import pika
import sys
import time

import actions
import config


class Stage(object):
  """Class for SNMP collector pipeline stages.

  This is the shared code between all pipeline stages.
  The flow is:
    * Listen on incoming queues
    * When a new Action arrives, execute it
     * Action will be called with the 'logic' as parameter
     * Action calls the logic
    * Result from the Action is pushed on the outgoing queue for that Action
  """

  def __init__(self, logic):
    self.name = logic.__class__.__name__
    self.logic = logic
    self.listen_to = set()
    self.to_purge = set()
    self.task_channel = None
    self.result_channel = None
    self.connection = None
    self.args = None
    self.started = False
    self._setup()

  def _setup(self):
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh = logging.FileHandler('/var/log/snmpcollector.log')
    fh.setFormatter(formatter)
    fh.setLevel(logging.INFO)
    root.addHandler(fh)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', '--debug', dest='debug', action='store_const', const=True,
        default=False, help='do not fork, print output to console')
    parser.add_argument(
        '-i', '--instance', dest='instance', default='default',
        help='specifiy instance id, used to run multiple instances')
    parser.add_argument('--pid', dest='pidfile', default=None,
        help='pidfile to write')
    self.args = parser.parse_args()

    if self.args.debug:
      root.setLevel(logging.DEBUG)
      ch = logging.StreamHandler(sys.stdout)
      ch.setLevel(logging.DEBUG)
      logging.getLogger('pika').setLevel(logging.ERROR)

      formatter = logging.Formatter( '%(asctime)s - %(name)s - '
          '%(levelname)s - %(message)s' )
      ch.setFormatter(formatter)
      root.addHandler(ch)

  def startup(self):
    assert not self.started
    mq = config.get('mq')
    credentials = pika.PlainCredentials(mq['username'], mq['password'])
    self.connection = pika.BlockingConnection(
        pika.ConnectionParameters(mq['host'], credentials=credentials))
    self.result_channel = self.connection.channel()
    logging.info('Started %s', self.name)
    self.started = True

  def shutdown(self):
    logging.info('Terminating %s', self.name)
    # This closes channels as well
    self.connection.close()

  def push(self, action, run, expire=None):
    properties = pika.BasicProperties(
        expiration=str(expire) if expire else None)
    self.result_channel.basic_publish(
        exchange='', routing_key=action.get_queue(self.args.instance),
        body=pickle.dumps((action, run), protocol=pickle.HIGHEST_PROTOCOL),
        properties=properties)

  def listen(self, action_cls):
    self.listen_to.add(action_cls)

  def _task_wrapper_callback(self, channel, method, properties, body):
    try:
      self._task_callback(channel, method, properties, body)
    except Exception as e:
      logging.exception('Unhandled exception in task loop:')
    finally:
      # Ack now, if we die during sending we will hopefully not crash loop
      channel.basic_ack(delivery_tag=method.delivery_tag)

  def _task_callback(self, channel, method, properties, body):
    start = time.time()
    action, run = pickle.loads(body)
    if not isinstance(action, actions.Action):
      logging.error('Got non-action in task queue: %s', repr(body))
      return

    generator = action.do(self.logic, run)
    if not generator:
      return

    # Mark the time we spent in this pipeline
    end = time.time()
    run.trace[self.name] = (start, end)

    for action in generator:
      self.push(action, run)

  def purge(self, action_cls):
    self.to_purge.add(action_cls)

  def run(self):
    if not self.listen_to:
      raise ValueError('Cannot run a stage that lacks an input queue')

    logging.info('Starting %s', self.name)

    # Needs to set up after daemonization
    self.startup()

    try:
      import procname
      procname.setprocname(self.name)
    except ImportError:
      pass

    if self.args.pidfile:
      with open(self.args.pidfile, 'w') as f:
        f.write(str(os.getpid()))

    self.task_channel = self.connection.channel()
    self.task_channel.basic_qos(prefetch_count=1)

    for action_cls in self.to_purge:
      task_queue = action_cls.get_queue(self.args.instance)
      self.task_channel.queue_declare(queue=task_queue)
      self.task_channel.queue_purge(queue=task_queue)
      logging.debug('Purged queue %s', task_queue)

    for action_cls in self.listen_to:
      task_queue = action_cls.get_queue(self.args.instance)
      self.task_channel.queue_declare(queue=task_queue)
      self.task_channel.basic_consume(
          self._task_wrapper_callback, queue=task_queue)
      logging.debug('Listening to queue %s', task_queue)

    try:
      self.task_channel.start_consuming()
    except KeyboardInterrupt:
      logging.error('Keyboard interrupt, shutting down..')
    except Exception as e:
      logging.exception('Unhandled exception, restarting stage')

    try:
      self.shutdown()
    except Exception as e:
      logging.exception('Exception in shutdown')
