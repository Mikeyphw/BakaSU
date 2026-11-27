#!/usr/bin/env python3
"""Private local persistence for the reviewed upstream event journal.

A stable owner-controlled directory is mandatory; CI scratch/cache artifacts
are not durable journal storage. Atomic replace and directory fsync prevent
partially written checkpoints. Locking serializes local competing writers.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import tempfile
from contextlib import contextmanager

from event_journal import canonical, digest, strict_json, validate, require


class LocalJournal:
    def __init__(self, path: Path):
        self.path = path.expanduser().absolute()
        self.folder = self.path.parent
        require(self.folder.is_dir() and not self.folder.is_symlink() and self.folder.resolve()==self.folder, 'JOURNAL_DIRECTORY_INVALID')
        mode=self.folder.stat()
        require(mode.st_uid==os.getuid() and mode.st_mode&0o077==0, 'JOURNAL_DIRECTORY_NOT_PRIVATE')

    @contextmanager
    def locked(self):
        fd=os.open(self.folder/('.'+self.path.name+'.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            self._regular(fd);fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    @staticmethod
    def _regular(fd):
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_mode&0o077==0,'JOURNAL_FILE_NOT_PRIVATE')

    def _read(self):
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            self._regular(f.fileno());value=strict_json(f.read(8_000_001))
        validate(value);return value

    def read(self):
        with self.locked():return self._read()

    def _persist(self, value):
        validate(value);data=canonical(value)
        require(len(data)<=8_000_000,'JOURNAL_TOO_LARGE')
        fd,name=tempfile.mkstemp(prefix='.journal-',dir=self.folder)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(data);f.flush();os.fsync(f.fileno())
            os.replace(name,self.path)
            parent=os.open(self.folder,os.O_DIRECTORY|os.O_RDONLY)
            try:os.fsync(parent)
            finally:os.close(parent)
        finally:Path(name).unlink(missing_ok=True)

    def initialize(self,value):
        with self.locked():
            require(not self.path.exists() and not self.path.is_symlink(),'JOURNAL_ALREADY_EXISTS')
            require(value.get('revision')==0,'INITIAL_JOURNAL_REVISION_INVALID')
            self._persist(value)

    def replace(self, expected, successor):
        with self.locked():
            before=self._read();require(digest(before)==digest(expected),'JOURNAL_CAS_MISMATCH')
            validate(successor)
            require(successor['revision']==before['revision']+1,'JOURNAL_REVISION_MISMATCH')
            require(successor['nextVersion']>=before['nextVersion'] and successor['versionFloor']>=before['versionFloor'],'JOURNAL_COUNTER_REGRESSION')
            from event_journal import utc
            require(utc(successor['checkpoint'])>=utc(before['checkpoint']),'JOURNAL_CHECKPOINT_REGRESSION')
            # History is immutable apart from lawful transitions of the most
            # recent attempt, and one-time promotion/reservation binding.
            for key,row in before['events'].items():
                target=successor['events'].get(key)
                require(isinstance(target,dict) and target['event']==row['event'],'JOURNAL_HISTORY_REMOVED_OR_CHANGED')
                require(target['reservation']==row['reservation'] or row['reservation'] is None,'JOURNAL_RESERVATION_CHANGED')
                require(target['promotion']==row['promotion'] or row['promotion'] is None,'JOURNAL_PROMOTION_CHANGED')
                a,b=row['attempts'],target['attempts']
                require(len(a)<=len(b)<=len(a)+1,'JOURNAL_ATTEMPT_HISTORY_CHANGED')
                for old,new in zip(a,b):
                    require(all(old[field]==new[field] for field in ('number','forkSha','intentId','legacy')),'JOURNAL_ATTEMPT_IDENTITY_CHANGED')
                    require(old['runId'] in (None,new['runId']),'JOURNAL_RUN_ID_CHANGED')
                    transitions={'intent':{'intent','observed','failed','qualified','not-sent'},'observed':{'observed','failed','qualified'},'failed':{'failed'},'qualified':{'qualified'},'not-sent':{'not-sent'}}
                    require(new['state'] in transitions[old['state']],'JOURNAL_ATTEMPT_REGRESSION')
                    if old['state'] in ('failed','qualified','not-sent'):require(old==new,'JOURNAL_TERMINAL_ATTEMPT_CHANGED')
            self._persist(successor)
