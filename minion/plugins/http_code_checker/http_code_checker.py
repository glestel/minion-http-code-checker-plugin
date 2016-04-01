# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import requests
import uuid

from minion.plugins.base import BlockingPlugin


class HTTPCodeCheckerPlugin(BlockingPlugin):
    PLUGIN_NAME = "HTTP Code Checker"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "light"

    # Instantiation of output
    report_dir = "/tmp/artifacts/"

    output_id = str(uuid.uuid4())

    logger = ""
    logger_path = report_dir + "logging_" + output_id + ".txt"

    # Configuration options
    user_agent = "minion http code checker"
    expected_code = 200

    target = ""

    def do_run(self):
        # Get the path to save output
        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
            self.logger_path = self.report_dir + "logging_" + self.output_id + ".txt"

        # Get the specified user-agent
        if "user-agent" in self.configuration:
            self.user_agent = self.configuration.get('user-agent')

        # Get the expected http code
        if "expected_code" in self.configuration:
            self.expected_code = self.configuration.get('expected_code')

        self.target = self.configuration['target']

        # create logger
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.FileHandler(self.logger_path)
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        logger.addHandler(ch)

        # Query the target
        try:
            # Set headers
            headers = {'User-Agent': self.user_agent}

            response = requests.get(self.target, headers=headers)

            # Get results
            http_code = response.status_code
            http_reason = response.reason

            # Check expected
            if http_code == self.expected_code:
                msg = "Got expected {} : {} with {}".format(http_code, http_reason, self.target)
                logger.info(msg)

            else:
                # Got wrong answer
                msg = "Got unexpected {} : {} with {} instead of {}"\
                    .format(http_code, http_reason, self.target, self.expected_code)
                logger.info(msg)

                # Build issue
                description = 'When sending a GET to {} with the user-agent {}, the response was {} : {} ' \
                              'instead of expected code {}'\
                    .format(self.target, self.user_agent, http_code, http_reason, self.expected_code)
                issue = {
                    'Severity': 'Medium',
                    'Summary': self.target + ' : wrong http response code',
                    'Description': description,
                    'URLs': [{'URL': self.target}],
                    'Classification': {
                        'cwe_id': '200',
                        'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
                    }
                }

                # Report issue
                issues = [issue]
                self.report_issues(issues)

            # Save logs and exit
            self._save_artifacts()
            self.report_finish(state=BlockingPlugin.EXIT_STATE_FINISHED)

        # Handle case the target can't be reached
        except Exception as e:
            msg = "Got unexpected {} with {}".format(e.message, self.target)
            logger.info(msg)

            # Save logs
            self._save_artifacts()

            failure = {
                "hostname": self.target,
                "exception": e.message,
                "message": "Could not reach target"
            }
            self._finish_with_failure(failure)

    # Function used to save output of the plugin
    def _save_artifacts(self):
        output_artifacts = [self.logger_path]

        if output_artifacts:
            self.report_artifacts("Schedule Output", output_artifacts)

    def do_stop(self):
        # Call parent method
        BlockingPlugin.do_stop(self)
