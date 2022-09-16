import json
import inspect
import sys
import time

# Import custom librairies
from pycheckpoint_api import Management
from pycheckpoint_api.models import Color
from pycheckpoint_api.management.exception import MandatoryFieldMissing, WrongType
import restfly

# Optional arguments
OPT_ARGS = {
    "add": [
        {"name": "set_if_exists", "annotation": bool, "accepted_values": [True, False]},
        {"name": "color", "annotation": str},
        {"name": "comments", "annotation": str},
        {"name": "details_level", "annotation": str},
        {"name": "groups", "annotation": list},
        {"name": "ignore_warnings", "annotation": str},
        {"name": "ignore_errors", "annotation": bool, "accepted_values": [True, False]},
    ],
    "delete": [
        {"name": "details_level", "annotation": str},
        {"name": "groups", "annotation": list},
        {"name": "ignore_warnings", "annotation": str},
        {"name": "ignore_errors", "annotation": bool, "accepted_values": [True, False]},
    ],
}

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets account information
    user_account = helper.get_user_credential("<account_name>")

    # The following example gets the setup parameters and prints them to the log
    instance_1_hostname = helper.get_global_setting("instance_1_hostname")
    helper.log_info("instance_1_hostname={}".format(instance_1_hostname))
    instance_1_port = helper.get_global_setting("instance_1_port")
    helper.log_info("instance_1_port={}".format(instance_1_port))
    instance_1_api_version = helper.get_global_setting("instance_1_api_version")
    helper.log_info("instance_1_api_version={}".format(instance_1_api_version))
    instance_1_domains = helper.get_global_setting("instance_1_domains")
    helper.log_info("instance_1_domains={}".format(instance_1_domains))
    instance_1_whitelist_policies = helper.get_global_setting("instance_1_whitelist_policies")
    helper.log_info("instance_1_whitelist_policies={}".format(instance_1_whitelist_policies))
    instance_1_ssl_verify = helper.get_global_setting("instance_1_ssl_verify")
    helper.log_info("instance_1_ssl_verify={}".format(instance_1_ssl_verify))
    instance_2_hostname = helper.get_global_setting("instance_2_hostname")
    helper.log_info("instance_2_hostname={}".format(instance_2_hostname))
    instance_2_port = helper.get_global_setting("instance_2_port")
    helper.log_info("instance_2_port={}".format(instance_2_port))
    instance_2_api_version = helper.get_global_setting("instance_2_api_version")
    helper.log_info("instance_2_api_version={}".format(instance_2_api_version))
    instance_2_domains = helper.get_global_setting("instance_2_domains")
    helper.log_info("instance_2_domains={}".format(instance_2_domains))
    instance_2_whitelist_policies = helper.get_global_setting("instance_2_whitelist_policies")
    helper.log_info("instance_2_whitelist_policies={}".format(instance_2_whitelist_policies))
    instance_2_ssl_verify = helper.get_global_setting("instance_2_ssl_verify")
    helper.log_info("instance_2_ssl_verify={}".format(instance_2_ssl_verify))
    instance_3_hostname = helper.get_global_setting("instance_3_hostname")
    helper.log_info("instance_3_hostname={}".format(instance_3_hostname))
    instance_3_port = helper.get_global_setting("instance_3_port")
    helper.log_info("instance_3_port={}".format(instance_3_port))
    instance_3_api_version = helper.get_global_setting("instance_3_api_version")
    helper.log_info("instance_3_api_version={}".format(instance_3_api_version))
    instance_3_domains = helper.get_global_setting("instance_3_domains")
    helper.log_info("instance_3_domains={}".format(instance_3_domains))
    instance_3_whitelist_policies = helper.get_global_setting("instance_3_whitelist_policies")
    helper.log_info("instance_3_whitelist_policies={}".format(instance_3_whitelist_policies))
    instance_3_ssl_verify = helper.get_global_setting("instance_3_ssl_verify")
    helper.log_info("instance_3_ssl_verify={}".format(instance_3_ssl_verify))

    # The following example gets the alert action parameters and prints them to the log
    instances = helper.get_param("instances")
    helper.log_info("instances={}".format(instances))

    account_usernames = helper.get_param("account_usernames")
    helper.log_info("account_usernames={}".format(account_usernames))

    action = helper.get_param("action")
    helper.log_info("action={}".format(action))

    name_template = helper.get_param("name_template")
    helper.log_info("name_template={}".format(name_template))

    automatic_publish_and_install = helper.get_param("automatic_publish_and_install")
    helper.log_info("automatic_publish_and_install={}".format(automatic_publish_and_install))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    # Get all instances concerned for this action
    instances = [
        str(i) for i in helper.get_param("instances").replace(" ", "").split(",")
    ]

    # Get all parameters from the action
    opt_account_usernames = json.loads(helper.get_param("account_usernames"))
    opt_action = helper.get_param("action")
    opt_name_template = helper.get_param("name_template")
    opt_enable_membership_resolution = helper.get_param("enable_membership_resolution")
    opt_automatic_publish_and_install = helper.get_param(
        "automatic_publish_and_install"
    )

    # Execute the action on each instance
    for instance in instances:

        # Get the client credentials for the current instance. If none, raise an issue
        client = helper.get_user_credential(opt_account_usernames[instance])
        if client is None:
            helper.log_error(
                "[CKPT-E-AUTH-ACCOUNT] Account can't be found. Did you configured the account under Configuration ? Did you mentionned the account username to use when raising this action ?"
            )
            sys.exit(1)
        helper.log_debug(
            '[CKPT-D-AUTH] Authentication will be done using the account "'
            + str(client["username"])
            + '"'
        )

        # Get all information relative to the instance from the global configuration
        hostname = helper.get_global_setting("instance_" + str(instance) + "_hostname")
        if hostname is None or hostname == "":
            helper.log_error(
                "[CKPT-E-HOSTNAME_NULL] No hostname was provided for instance nÂ°"
                + str(instance)
                + ", check your configuration"
            )
            sys.exit(1)

        port = helper.get_global_setting("instance_" + str(instance) + "_port")
        if port is None or port == "":
            helper.log_error(
                "[CKPT-E-PORT_NULL] No port was provided for instance nÂ°"
                + str(instance)
                + ", check your configuration"
            )
            sys.exit(1)

        api_version = helper.get_global_setting(
            "instance_" + str(instance) + "_api_version"
        )
        if api_version is None or api_version == "":
            helper.log_error(
                "[CKPT-E-API_VERSION_NULL] No API Version was provided for instance n°"
                + str(instance)
                + ", check your configuration"
            )
            sys.exit(1)

        # Get all domains impacted
        domains = helper.get_global_setting("instance_" + str(instance) + "_domains")
        if domains is not None:
            domains = domains.replace(" ", "").split(",")
        else:
            # If no domain, we have an empty array
            domains = [""]

        # Get all whitelisted policies
        whitelisted_policies = helper.get_global_setting(
            "instance_" + str(instance) + "_whitelist_policies"
        )
        if whitelisted_policies is None or whitelisted_policies == "":
            # If no whitelist is provided, keep it as none
            whitelisted_policies = None
        else:
            whitelisted_policies = whitelisted_policies.replace(" ", "").split(",")

        # Check if we need to verify the certificate validity or not
        ssl_verify = (
            True
            if helper.get_global_setting("instance_" + str(instance) + "_ssl_verify")
            == 1
            else False
        )

        # Execute the action on each domain of the instance
        for domain in domains:

            # Get events
            events = helper.get_events()

            # Instanciate the Checkpoint object with given inputs
            with Management(
                hostname=hostname,
                port=int(port),
                user=client["username"],
                password=client["password"],
                version=api_version,
                domain=domain,
                ssl_verify=ssl_verify,
            ) as firewall:
                helper.log_debug(
                    "[CKPT-D-CKPT_OBJECT] Checkpoint Management connection object is created successfully"
                )
                # From now, we have a valid connection to the firewall
                # For each event, we process the results
                for event in events:
                    # Try to determine the type of the object. We need a valid/known type from the library
                    if "type" in event:
                        if event["type"] in dir(firewall.network_objects):
                            if opt_name_template is not None or opt_name_template != "":
                                # Change the name with the template
                                event["name"] = opt_name_template.format(**event)

                            # From the type, we deduce the function "add" to call from all network objects
                            func = getattr(
                                getattr(
                                    firewall.network_objects,
                                    event["type"].replace("-", "_"),
                                ),
                                opt_action,
                            )
                            # Validate the function with the event
                            params = validate_function(helper, func, event)

                            # Sanitize some parameters if needed
                            if "color" in params:
                                params["color"] = Color(params["color"])

                            helper.log_debug(
                                "Call function: "
                                + str(func)
                                + " with sanitized parameters: "
                                + str(params)
                            )

                            # Execute the action (call the function)
                            resp = None
                            try:

                                resp = func(**params)
                                helper.log_info(
                                    "[CKPT-I-REQUEST_SUCCESS] 🟢 Request for object name '"
                                    + str(params["name"])
                                    + "' was successful"
                                )

                            except (MandatoryFieldMissing, WrongType) as e:
                                helper.log_error(
                                    "[CKPT-E-LIBRARY_ERROR] 🔴 Your request raised an issue: "
                                    + str(e)
                                )
                            except restfly.errors.BadRequestError as e:
                                helper.log_error(
                                    "[CKPT-E-BAD_REQUEST] 🔴 Your request is not correct and was rejected by Checkpoint: "
                                    + str(e.msg.replace('"', "'"))
                                )
                            except Exception as e:
                                helper.log_error(
                                    "[CKPT-E-GENERIC_EXCEPTION] 🔴 "
                                    + str(e.msg.replace('"', "'"))
                                )

                            helper.log_debug(
                                "Response from Checkpoint Manager: " + str(resp)
                            )

                        else:
                            helper.log_error(
                                "[CKPT-E-WRONG_TYPE] 🔴 You didn't provided  a valid type for the object (type is '"
                                + event["type"]
                                + "'). Please refer to the documentation"
                            )
                    else:
                        helper.log_error(
                            "[CKPT-E-NO_TYPE] 🔴 You didn't provided any type for the object. Field 'type' is null"
                        )

                helper.log_info("[CKPT-I-ACTION] Chosen action is: "+opt_automatic_publish_and_install)

                # If execute and discard is selected, it means that we just want to test the API results, so we drop
                # all the changes
                if opt_automatic_publish_and_install == "execute_discard":
                    helper.log_info("[CKPT-I-ACTION_DISCARD] Discard is requested")
                    firewall.session.discard()

                # If automatic publish is selected, then publish
                if opt_automatic_publish_and_install in ["publish", "publish_install"]:
                    # Automatic publish is enabled so we publish the changes
                    helper.log_info("[CKPT-I-ACTION_PUBLISH] Publish is requested")
                    firewall.session.publish()

                # Wait 2 seconds
                time.sleep(2)

                if opt_automatic_publish_and_install == "publish_install":
                    # Automatic install after publish
                    helper.log_info("[CKPT-I-ACTION_INSTALL] Install is requested")
                    # Get packages
                    packages = firewall.policy.package.show_packages(
                        details_level="full"
                    ).packages
                    # For each package, install the policy
                    for p in packages:
                        if (
                            whitelisted_policies is None
                            or p.name in whitelisted_policies
                        ):
                            targets = [t.name for t in p.installation_targets]
                            helper.log_info(targets)
                            resp = firewall.policy.install_policy(
                                policy_package=p.uid, targets=targets
                            )

    return 0


# This function is used to validate inputs for the given function
# It's returning the dictionary with all parameters
def validate_function(helper, func, event):

    # Log on which event we are working on
    helper.log_debug(
        "[CKPT-D-FUNC] Validating following event for the function ("
        + func.__name__
        + "): "
        + str(event)
    )

    # Prepare final dictionnary
    params = {}

    helper.log_debug(
        "[CKPT-D-VALID1] (#1) Validating parameters from function signature"
    )
    # /1 Check all parameters from the function signature
    signature = inspect.signature(func)
    for sig_name, sig_values in signature.parameters.items():
        # Remove false positives:
        if sig_name not in ["kwargs", "kw"]:
            param = process_param(
                helper, event, sig_name, sig_values.annotation, sig_values.default
            )
            params[sig_name] = param

    helper.log_debug(
        "[CKPT-D-VALID2] (#2) Validating parameters for optional arguments"
    )
    # /2 Check all optional parameters for the given function
    if func.__name__ in OPT_ARGS:
        opt_args = OPT_ARGS[func.__name__]
        for arg in opt_args:
            param = process_param(helper, event, arg["name"], arg["annotation"], None)
            if "accepted_values" in arg:
                if param not in arg["accepted_values"] and param is not None:
                    helper.log_error(
                        "[CKPT-E-ACCEPTED_VALUES] Provided value ("
                        + str(param)
                        + ") for the parameter ("
                        + arg["name"]
                        + " is not accepted as it's expected only one of these values: "
                        + str(arg["accepted_values"])
                        + ". Please refer to the original python library code to verify which fields are expected"
                    )
                    sys.exit(1)
                elif param is not None:
                    params[arg["name"]] = param
                else:
                    helper.log_debug(
                        "[CKPT-D-OPTIONAL_ARG_NONE] Optional argument "
                        + arg["name"]
                        + " will not be added in the payload as it's value is None"
                    )
            else:
                if param is not None:
                    params[arg["name"]] = param

    helper.log_debug("[CKPT-D-FINAL_PARAMS] Params built from event: " + str(params))
    return params


# This function is used to get the final value and validate the type
def process_param(helper, event, sig_name, sig_annotation, sig_default):

    helper.log_debug(
        "[CKPT-D-PROCESS_PARAMS_INPUT] Processing parameter with following inputs: event="
        + str(event)
        + ", sig_name="
        + str(sig_name)
        + ", sig_annotation="
        + str(sig_annotation)
        + ", sig_default="
        + str(sig_default)
    )

    # Default is None
    value = None
    try:
        value = event[sig_name]
    except KeyError as e:
        if sig_default is inspect._empty:
            helper.log_error(
                "[CKPT-E-FIELD_NOT_PRESENT] An expected field ("
                + sig_name
                + ") is not present in the event (and no default value was found). Please refer to the original python library code to verify which fields are expected"
            )
            sys.exit(1)
        else:
            helper.log_debug(
                "[CKPT-D-FIELD_NOT_PRESENT_DEFAULT] An expected field ("
                + sig_name
                + ") is not present but a default value will be used: "
                + str(value)
                + ". Please refer to the original python library code to verify which fields are expected"
            )
            value = sig_default
    helper.log_debug(
        "[CKPT-D-TYPE_PROCESSING] Type for "
        + sig_name
        + " need to be "
        + str(sig_annotation)
        + ", processing it..."
    )
    # Avoid adding none values
    if value is not None:
        # Process data with the expected type
        if sig_annotation is int:
            value = int(value)
        elif sig_annotation is str:
            value = str(value)
        elif sig_annotation is list:
            value = value.replace(", ", ",").split(",")
        elif sig_annotation is bool:
            if value in ["0", "false"]:
                value = False
            else:
                value = True
        elif sig_annotation is inspect._empty:
            helper.log_error(
                "[CKPT-E-EMPTY-TYPE] This error should come from the pycheckpoint_api library on which a field has no type defined. Please check this information for the field '"
                + str(sig_name)
                + "'"
            )
            sys.exit(1)
        else:
            helper.log_error(
                "[CKPT-E-UNSUPPORTED_TYPE] Unsupported type for parameter: "
                + str(sig_annotation)
            )
            sys.exit(1)
    return value
