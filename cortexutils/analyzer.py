#!/usr/bin/env python
# encoding: utf-8

import json
import os

from cortexutils.extractor import Extractor
from cortexutils.worker import Worker
from shutil import copyfileobj
import tempfile
import ntpath


class Analyzer(Worker):

    def __init__(self, job_directory=None):
        Worker.__init__(self, job_directory)

        # Not breaking compatibility
        self.artifact = self._input

        # Check for auto extraction config
        self.auto_extract = self.get_param('config.auto_extract', self.get_param('config.auto_extract_artifacts', True))

    def get_data(self):
        """Wrapper for getting data from input dict.

        :return: Data (observable value) given through Cortex"""
        if self.data_type == 'file':
            return self.get_param('filename', None, 'Missing filename.')
        else:
            return self.get_param('data', None, 'Missing data field')

    def get_param(self, name, default=None, message=None):
        data = super(Analyzer, self).get_param(name, default, message)
        if name == 'file' and self.data_type == 'file' and self.job_directory is not None:
            path = '%s/input/%s' % (self.job_directory, data)
            if os.path.isfile(path):
                return path
        else:
            return data

    def build_taxonomy(self, level, namespace, predicate, value):
        """
        :param level: info, safe, suspicious or malicious
        :param namespace: Name of analyzer
        :param predicate: Name of service
        :param value: value
        :return: dict
        """
        # Set info level if something not expected is set
        if level not in ['info', 'safe', 'suspicious', 'malicious']:
            level = 'info'
        return {
            'level': level,
            'namespace': namespace,
            'predicate': predicate,
            'value': value
        }

    def summary(self, raw):
        """Returns a summary, needed for 'short.html' template. Overwrite it for your needs!

        :returns: by default return an empty dict"""
        return {}

    def artifacts(self, raw):
        # Use the regex extractor, if auto_extract setting is not False
        if self.auto_extract:
            extractor = Extractor(ignore=self.get_data())
            return extractor.check_iterable(raw)

        # Return empty list
        return []

    def build_artifact(self, data_type, data, **kwargs):
        if data_type == 'file':
            if os.path.isfile(data):
                (dst, filename) = tempfile.mkstemp(dir=os.path.join(self.job_directory, "output"))
                with open(data, 'r') as src:
                    copyfileobj(src, os.fdopen(dst, 'w'))
                    kwargs.update({'dataType': data_type, 'file': ntpath.basename(filename),
                                   'filename': ntpath.basename(data)})
                    return kwargs
        else:
            kwargs.update({'dataType': data_type, 'data': data})
            return kwargs

    def report(self, full_report, ensure_ascii=False):
        """Returns a json dict via stdout.

        :param full_report: Analyzer results as dict.
        :param ensure_ascii: Force ascii output. Default: False"""

        summary = {}
        try:
            summary = self.summary(full_report)
        except Exception:
            pass

        super(Analyzer, self).report({
            'success': True,
            'summary': summary,
            'artifacts': self.artifacts(full_report),
            'full': full_report
        }, ensure_ascii)

    def run(self):
        """Overwritten by analyzers"""
        pass

    # Not breaking compatibility
    def notSupported(self):
        self.error('This datatype is not supported by this analyzer.')

    # Not breaking compatibility
    def unexpectedError(self, e):
        self.error('Unexpected Error: ' + str(e))

    # Not breaking compatibility
    def getData(self):
        """For not breaking compatibility to cortexutils.analyzer, this wraps get_data()"""
        return self.get_data()

    # Not breaking compatibility
    def getParam(self, name, default=None, message=None):
        """For not breaking compatibility to cortexutils.analyzer, this wraps get_param()"""
        return self.get_param(name=name, default=default, message=message)

    # Not breaking compatibility
    def checkTlp(self, message):
        if not (self.__check_tlp()):
            self.error(message)
