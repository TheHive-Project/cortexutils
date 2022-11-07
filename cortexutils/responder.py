#!/usr/bin/env python
# encoding: utf-8

import json
import os
from cortexutils.worker import Worker


class Responder(Worker):

    def __init__(self, job_directory=None, secret_phrases=None):
        Worker.__init__(self, job_directory, secret_phrases)

        # Not breaking compatibility
        self.artifact = self._input

    def get_data(self):
        """Wrapper for getting data from input dict.

        :return: Data (observable value) given through Cortex"""
        return self.get_param('data', None, 'Missing data field')

    def report(self, full_report, ensure_ascii=False):
        """Returns a json dict via stdout.

        :param full_report: Responsder results as dict.
        :param ensure_ascii: Force ascii output. Default: False"""

        operation_list = []
        try:
            operation_list = self.operations(full_report)
        except Exception:
            pass
        super(Responder, self).report({
            'success': True,
            'full': full_report,
            'operations': operation_list
        }, ensure_ascii)

    def run(self):
        """Overwritten by responders"""
        pass
