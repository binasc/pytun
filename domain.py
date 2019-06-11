import ntpath
import re

from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer

import loglevel

_logger = loglevel.get_logger('domain')
_logger.setLevel(loglevel.DEFAULT_LEVEL)

class Domain(object):

    def __init__(self, blocked_file, poisoned_file):
        self._blocked_file = blocked_file
        self._blocked_domain = set()
        self._poisoned_file = poisoned_file
        self._poisoned_domain = set()

        self.load_blocked_domain()
        self.load_poisoned_domain()

        self._event_handler = MyHandler(self, ntpath.basename(self._blocked_file))
        self._observer = Observer()
        path = ntpath.dirname(self._blocked_file)
        if path == '':
            path = '.'
        self._observer.schedule(self._event_handler, path=path, recursive=False)
        self._observer.start()

    def load_blocked_domain(self):
        try:
            fp = open(self._blocked_file, 'r')
        except IOError as e:
            _logger.warning("Failed to open %s: %s", self._blocked_file, str(e))
            return False
        new_blocked_domain = set()
        for line in fp.readlines():
            line = line.strip()
            if len(line) == 0 or line.startswith('#'):
                continue
            new_blocked_domain.add(line)
        fp.close()
        self._blocked_domain = new_blocked_domain
        _logger.info('Updated %d blocked items', len(new_blocked_domain))

    def update_poisoned_domain(self, domain):
        parts = domain.split('.')
        if len(parts) > 0 and len(parts[-1].strip()) == 0:
            parts = parts[: -1]
        if len(parts[-1]) == 2:
            name = '.'.join(parts[-3:]) + '.'
        else:
            name = '.'.join(parts[-2:]) + '.'
        old_len = len(self._poisoned_domain)
        self._poisoned_domain.add(name)
        if len(self._poisoned_domain) != old_len:
            try:
                fp = open(self._poisoned_file, 'w')
                fp.write('\n'.join(self._poisoned_domain))
                fp.close()
                _logger.info("Synced %d poisoned domains", len(self._poisoned_domain))
            except IOError as e:
                _logger.warning("Failed to open %s: %s", self._poisoned_file, str(e))

    def load_poisoned_domain(self):
        try:
            fp = open(self._poisoned_file, 'r')
        except IOError as e:
            _logger.warning("Failed to open %s: %s", self._poisoned_file ,str(e))
            return
        new_poisoned_domain = set()
        for line in fp.readlines():
            line = line.strip()
            if len(line) == 0 or line.startswith('#'):
                continue
            new_poisoned_domain.add(line)
        fp.close()
        self._poisoned_domain = new_poisoned_domain
        _logger.info('loaded %d poisoned items', len(new_poisoned_domain))

    def is_blocked(self, domain):
        m = re.search('([^.]+\.){2}[^.]{2}\.$', domain)
        if m is not None and (m.group(0) in self._blocked_domain or m.group(0) in self._poisoned_domain):
            return True
        else:
            m = re.search('[^.]+\.[^.]+\.$', domain)
            if m is not None and (m.group(0) in self._blocked_domain or m.group(0) in self._poisoned_domain):
                return True
        return False

class MyHandler(PatternMatchingEventHandler):

    def __init__(self, domain, file):
        super(MyHandler, self).__init__(patterns=['*' + file])
        self._domain = domain

    def on_modified(self, event):
        self._domain.load_blocked_domain()

    def on_created(self, event):
        self._domain.load_blocked_domain()
