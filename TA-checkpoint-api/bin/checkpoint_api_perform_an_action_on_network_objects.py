
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_checkpoint_api_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_checkpoint_api_perform_an_action_on_network_objects_helper

class AlertActionWorkercheckpoint_api_perform_an_action_on_network_objects(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkercheckpoint_api_perform_an_action_on_network_objects, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_global_setting("instance_1_hostname"):
            self.log_error('instance_1_hostname is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_global_setting("instance_1_port"):
            self.log_error('instance_1_port is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_global_setting("instance_1_api_version"):
            self.log_error('instance_1_api_version is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_param("instances"):
            self.log_error('instances is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("account_usernames"):
            self.log_error('account_usernames is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("action"):
            self.log_error('action is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("name_template"):
            self.log_error('name_template is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("automatic_publish_and_install"):
            self.log_error('automatic_publish_and_install is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_checkpoint_api_perform_an_action_on_network_objects_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkercheckpoint_api_perform_an_action_on_network_objects("TA-checkpoint-api", "checkpoint_api_perform_an_action_on_network_objects").run(sys.argv)
    sys.exit(exitcode)
