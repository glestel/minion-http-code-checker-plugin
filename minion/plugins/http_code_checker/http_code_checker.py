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

    API_PATH = "http://127.0.0.1:8383"

    # Instantiation of output
    report_dir = "/tmp/artifacts/"

    output_id = str(uuid.uuid4())

    logger = ""
    logger_path = report_dir + "logging_" + output_id + ".txt"

    # Configuration options
    user_agent = "minion http code checker"
    expected_code = 200
    enforce_ssl = True

    targets = []
    groups_targets = []

    create_info_on_success = False
    info_success = ""

    def do_run(self):
        # Get the path to save output
        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
            self.logger_path = self.report_dir + "logging_" + self.output_id + ".txt"

        # Get the path to the api
        if 'api_path' in self.configuration:
            self.API_PATH = self.configuration['api_path']

        # Get the specified user-agent
        if "user-agent" in self.configuration:
            self.user_agent = self.configuration.get('user-agent')

        # Get the expected http code
        if "expected_code" in self.configuration:
            self.expected_code = self.configuration.get('expected_code')

        # Check if the target used to launch the scan need to be included
        if self.configuration.get("include_calling_target"):
            self.targets.append(self.configuration['target'])

        # Check if the plugin needs to get groups of targets from minion
        if "groups_targets" in self.configuration:
            self.groups_targets = self.configuration.get('groups_targets')

        # Check if the SSL verification needs to be enforced
        if "enforce_ssl" in self.configuration:
            self.enforce_ssl = self.configuration['enforce_ssl']

        # Check if successful request must be stored in info
        if self.configuration.get("store_success"):
            self.create_info_on_success = True

            # Create Info issue
            self.info_success = {
                'Severity': 'Info',
                'Summary': 'Right HTTP response code',
                'Description': 'Target responded with expected {} code on GET request'.format(self.expected_code),
                'URLs': []
            }

        # create logger
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.FileHandler(self.logger_path)
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.logger.addHandler(ch)

        # Populate the target list if needed
        if self.groups_targets:
            self.populate_targets()

        # Launch request
        for target in self.targets:
            self.query_target(target)

        # Report success
        if self.create_info_on_success:
            self.report_issue(self.info_success)

        # Save logs and exit
        self._save_artifacts()
        self.report_finish(state=BlockingPlugin.EXIT_STATE_FINISHED)

    def populate_targets(self):
        # Retrieve every target for every group
        for group in self.groups_targets:
            try:
                r = requests.get(self.API_PATH + "/groups/" + group)
                r.raise_for_status()
            except Exception as e:
                self.logger.error(e.message)

            # Check the request is successful
            success = r.json()["success"]
            if not success:
                msg = "Could not retrieve info about group {} because {}".format(group, r.json()["reason"])
                self.logger.error(msg)
            # Add result to target list
            self.targets.extend(r.json()["group"]['sites'])

    def query_target(self, current_target):
        # Query the target
        try:
            # Set headers
            headers = {'User-Agent': self.user_agent}

            response = requests.get(current_target, headers=headers, verify=self.enforce_ssl)

            # Get results
            http_code = response.status_code
            http_reason = response.reason

            # Check expected
            if http_code == self.expected_code:
                msg = "Got expected {} : {} with {}".format(http_code, http_reason, current_target)
                self.logger.info(msg)

                # Add url to info if needed
                if self.create_info_on_success:
                    self.info_success['URLs'].append({'URL': current_target})

            else:
                # Got wrong answer
                msg = "Got unexpected {} : {} with {} instead of {}" \
                    .format(http_code, http_reason, current_target, self.expected_code)
                self.logger.info(msg)

                # Build issue
                description = 'When sending a GET to {} with the user-agent {}, the response was {} : {} ' \
                              'instead of expected code {}' \
                    .format(current_target, self.user_agent, http_code, http_reason, self.expected_code)
                issue = {
                    'Severity': 'Medium',
                    'Summary': current_target + ' : wrong http response code',
                    'Description': description,
                    'URLs': [{'URL': current_target}],
                    'Classification': {
                        'cwe_id': '200',
                        'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
                    }
                }

                # Report issue
                issues = [issue]
                self.report_issues(issues)

        # Handle case the target can't be reached
        except Exception as e:
            msg = "Got unexpected {} with {}".format(e.message, current_target)
            self.logger.warning(msg)

    # Function used to save output of the plugin
    def _save_artifacts(self):
        output_artifacts = [self.logger_path]

        if output_artifacts:
            self.report_artifacts("HTTP Checker Output", output_artifacts)

    def do_stop(self):
        # Call parent method
        BlockingPlugin.do_stop(self)
