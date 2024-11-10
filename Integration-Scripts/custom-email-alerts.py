"""
It is a Custom Email Alert (Formatter) for Email
It provides a HTML Email based formatting for the JSON WaZuh Alerts
It is a Generic Script i.e will work for all WaZuh Alert Logs.

How To?

>> Step 1: Setup the Script File

Add this Script inside: /var/ossec/integrations/

With Permission set to
chown root:wazuh /var/ossec/integrations/custom-alerts-email.py
chmod 750 /var/ossec/integrations/custom-alerts-email.py

>> Step2: Integration in WaZuh

Use the Below XML Section inside WaZuh Manager ossec.conf
========

<!-- For GuardDuty: Custom GuardDuty Formatter -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>aws_guardduty</group>
    <api_key>Guardduty</api_key>
    <alert_format>json</alert_format>
</integration>

<!-- For FIM: Custom FIM Formatter -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>syscheck</group>
    <api_key>FIM</api_key>
    <alert_format>json</alert_format>
</integration>

<!-- For SG: Custom SecurityGroups Formatter -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>aws_cloudtrail_securitygroups</group> <!-- A Custom Group in rules need to be created which has all SG related Events -->
    <api_key>SecurityGroups</api_key>
    <alert_format>json</alert_format>
</integration>

<!-- For Any: Custom for Any - Set blank for api_key -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>ossec</group>
    <api_key></api_key>
    <alert_format>json</alert_format>
</integration>

"""

import os
import sys
import json

import copy

import smtplib
from email.message import EmailMessage

from dateutil.parser import parse as date_parser
import pytz

import html

import logging

## Change this as per Setup
ENV = "Production"
WAZUH_HOST = "https://{ENV}.security-insights.com"
SERVICE="WaZuh"

# Footer for Email
FROM_TEAM = "SecOps Team"
FROM_TEAM_EMAIL = "alerts@security-insights.com"

# AWS required JSON
AWS_ACCOUNT_NAMES = {
    "1XXXXXXXXXXX": "AWS Dev",
    "2XXXXXXXXXXX": "AWS UAT",
    "3XXXXXXXXXXX": "AWS Production"
}

# Get Script Name
SCRIPT_NAME = os.path.basename(sys.argv[0])

# Exclude Few Fields
FIELD_EXCLUSION = [
    "Instancedetails - Imageid",
    "Instancedetails - Instancetype",
    "Instancedetails - Productcodes",
    "Instancedetails - Availabilityzone",
    "Servicename",
    "Detectorid",
    "Archived",
    "Eventfirstseen",
    "Eventlastseen",
    "Count",
    "Additionalinfo - Value"
]

# Whiltelist IP
WAZUH_CDB_WHITELIST_FILE = "/var/ossec/etc/lists/email-alert-whitelist"


# Email Details
EMAIL_FROM = f"{ENV}@security-insights.com"
EMAIL_SERVER = '127.0.0.1'
EMAIL_PORT = 25

# Logging Info
WAZUH_ROOT="/var/ossec"
WAZUH_INTEGRATION_LOGS=f"{WAZUH_ROOT}/logs/integrations.log"


try:
    logging.basicConfig(
        format=f'%(asctime)s: [{SCRIPT_NAME}]: %(levelname)s: %(message)s',
        datefmt='%a %d %b %H:%M:%S %p %Z %Y',
        filename=WAZUH_INTEGRATION_LOGS,
        encoding='utf-8',
        level=logging.INFO,
    )

    if not os.path.exists(WAZUH_INTEGRATION_LOGS):
        raise FileNotFoundError
except (FileNotFoundError, PermissionError):

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logging.warning(f"Could not create log file '{WAZUH_INTEGRATION_LOGS}', falling back to console logging.")

logger = logging.getLogger(__name__)


"""

{
    "rule": {},
    "summary_json": {
        "Name": "",
        "Count": ""
    },
    "summary_preview": "",
    "subject": "",
    "detailed_html_json": {
        "Service Affected Detailed Analysis": {},
        "Resource Affected Detailed Analysis": {}
    },
    "summary_html_json": {
        "title": "",
        "html": ""
    }
}


"""


######################################## HELPER FUNCTIONS #######################################

# Get WaZuh CDB whitelist
def get_cdb_whitelist():
    cdb_whitelist = []
    try:

        file_reader = open(WAZUH_CDB_WHITELIST_FILE, "r")

        for one_line in file_reader.readlines():
            cdb_whitelist.append(one_line.split(":")[0])

        return cdb_whitelist

    except Exception:

        logger.error(f'File [{WAZUH_CDB_WHITELIST_FILE}] does not exist')
        return []



# Convert JSON to Flattened JSON Depth 1
def flat_it(json_obj):
    new_dict = {}
    for f,v in json_obj.items():
        if type(v) is dict:
            for f1,v1 in v.items():
                f = f[0].title() + f[1:]
                f1 = f1[0].title() + f1[1:]
                new_dict[f + "-" + f1] = v1
        else:
            f = f[0].title() + f[1:]
            new_dict[f] = v
    return new_dict


# Check if number (inside str)
def is_int(str_string):
    try:
        str_string_int = int(str_string)
        return True
    except Exception as expect_me:
       return False


# Check if String is a Valid Date
def is_valid_date(date_string):
    try:
        parsed_date = date_parser(date_string)
        timezone_ist = pytz.timezone('Asia/Kolkata')
        if is_int(date_string):
            return None
        return parsed_date.astimezone(timezone_ist).strftime('%a %d %b %H:%M:%S %p %Z %Y')
    except Exception as expect_me:
       return None


# Convert to a Desired Date Format
def convert_to_dformat(date_string):
    valid_date = is_valid_date(date_string)
    if valid_date:
        return valid_date
    else:
        return date_string


# Get a File Base Directory and file name
def get_dir_and_file(path):
    _dir = os.path.dirname(path)
    core_dir = ""
    _dir2check = _dir.split("/")
    if len(_dir2check) > 2:
        _sub_dir = _dir2check[:3]
        core_dir = "/".join(_sub_dir)
    else:
        core_dir = "/".join(_dir2check)
    _file = os.path.basename(path)
    return { "dir": _dir, "file": _file, "core_dir": core_dir, "path": path }



## Format Syscheck Audit
def format_syscheck_audit(audit_json):

    '''
    Reference Link: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html

    login_user // User who was logged In via SSH
    effective_user // root
    user // root
    group // root
    process // Process that modified this

    '''

    audit_who_list = []
    audit_process_details = ""

    if audit_json == "{}" or audit_json == {}:
        audit_who_list = ["<b> No Whodata found in the Alert </b>"]
        audit_process_details = ""


        return f'''
            <tr>
                <td id="onlyforpadding_left">&nbsp;</td>
                <td style="padding:0px 0px; vertical-align:top; padding: 6px; background-color: #f8d7da; border-left: 4px solid rgb(170, 74, 68)">
                    <p>
                        &nbsp; &nbsp; <span style="font-size: 40px; padding-right: 10px;color: #721c24;">&#9888;</span>
                        <span style="vertical-align:super; font-size: 16px; font-weight: bold; color: #721c24;">No Whodata details was provided by Wazuh Agent</span>
                    </p>
                    <p> To Identify Root Cause </p>
                    <span>&#8611;</span> Check If whodata attribute is enabled for this File Path. <br>
                    <span>&#8611;</span> Check If `auditd` is installed in this Agent and it is running. <br>
                    <span>&#8611;</span> Check for audit config using command `auditctl -l` (this shows all dir monitored by auditd) <br>
                </td>
                <td id="onlyforpadding_right">&nbsp;</td>
            </tr>
        '''

    for one_audit_field in audit_json:

        one_audit_description = audit_json[one_audit_field]

        formatted_description = ""

        formatted_field = " ".join([one_str.title() for one_str in one_audit_field.split("_")])

        formatted_extra_info = ""

        if one_audit_field == "process":
            _sub_description_list = []
            for _sub_description in one_audit_description:
                _sub_description_list.append(
                    f'{_sub_description} ({one_audit_description[_sub_description]}) <br />'
                )

            audit_process_details = f'''
                <p style="margin:0 0 10px 0">
                    <span style="font-weight:bold">Process</span> <br>
                    {" ".join(_sub_description_list)}
                </p>
            '''

        else:

            if one_audit_description.get("name") and one_audit_description.get("id"):
                formatted_description = f'{one_audit_description.get("name")} ({one_audit_description.get("id")})'
            elif one_audit_description.get("name"):
                formatted_description = f'{one_audit_description.get("name")}'
            else:
                formatted_description = f'{one_audit_description}'

            audit_who_list.append(f'''
                <p style="margin:0 0 10px 0;">
                    <span style="font-weight:bold">{formatted_field}</span> <br>
                    {formatted_description}
                </p>
            ''')

    return f'''
        <tr>
            <td id="onlyforpadding_left">&nbsp;</td>
            <td id="head_name" style="font-size:24px;padding: 0px 10px 0px 0px;">
                <b>WHO data(auditd)</b>
            </td>
            <td id="onlyforpadding_right">&nbsp;</td>
        </tr>
        <tr>
            <td id="onlyforpadding_left">&nbsp;</td>
            <td class="body_details" style="border: solid 1px #ddd; padding:10px 10px 10px 10px;">
                <table width="100%" border="0" cellspacing="0" cellpadding="0">
                    <tbody>
                        <tr>
                        <td style="width:50%;padding:0px 0px;vertical-align:top">
                            {" ".join(audit_who_list)}
                        </td>
                        <td style="width:50%;padding:0px;vertical-align:top">
                            {audit_process_details}
                        </td>
                        </tr>
                    </tbody>
                </table>
            </td>
            <td id="onlyforpadding_right">&nbsp;</td>
        </tr>
    '''



## Filter JSON Fields
def filter_json(str_json, FILTER):

    reduced_json = {}

    section_json = flat_it(copy.deepcopy(str_json))

    for field, description in section_json.items():
        name = field.replace("_"," ").replace("-"," - ").title();

        if name not in FILTER:
            reduced_json[name] = description

    return reduced_json



# AWS UserIdentity Formatting
def get_useridentity(useridentity):

    user_type = useridentity['type']
    user_arn = useridentity['arn']
    user_role = None
    user_name = user_arn.split("/")[-1]

    if user_type == "AssumedRole":
        user_role = user_arn.split("/")[-2]
        if user_role.startswith("AWSReservedSSO"):
            _user_role = user_role.split("_")
            user_role = _user_role[1]
    elif user_type == "Root":
        user_role = "Root"
    elif user_type == "IAMUser":
        user_type = '<strong style="color:red">IAMUser</strong>'
    else:
        user_role = None

    user_details = {
        "Name": user_name,
        "Type": user_type,
        "Role": user_role
    }

    return user_details


## Extract the Rule Details
def get_address(item_json, direction):

    if item_json.get("ipRanges"):

        ipv4 = item_json["ipRanges"]["items"][0]
        return {
            direction : f'IPv4 / {ipv4.get("cidrIp")}',
            "SG Description": ipv4.get("description", '<strong style="color:red">No Description Added</strong>')
        }

    elif item_json.get("ipv6Ranges"):

        ipv6 = item_json["ipv6Ranges"]["items"][0]

        return {
            direction : f'IPv6 / {ipv6.get("cidrIpv6")}',
            "SG Description": ipv6.get("description", '<strong style="color:red">No Description Added</strong>')
        }

    elif item_json.get("prefixListIds"):

        prefix_list = item_json["prefixListIds"]["items"][0]

        return {
            direction : f'PrefixListId / {prefix_list.get("prefixListId")}',
            "SG Description": prefix_list.get("description", '<strong style="color:red">No Description Added</strong>')
        }

    elif item_json.get("groups"):

        sg_item = item_json["groups"]["items"][0]

        return {
            direction : f'SG Id / {sg_item.get("groupId")}',
            "SG Description": sg_item.get("description", '<strong style="color:red">No Description Added</strong>')
        }

    else:

        return f'Item / {item_json}'


## Extract & Format the Rule Details
def get_rule_breakdown(item_json, event_name):

    from_port = item_json.get("fromPort", "-1")
    to_port = item_json.get("toPort", "-1")
    protocol = item_json["ipProtocol"]

    port_protocol = f'{from_port}-{to_port}/{protocol}'

    if protocol == "icmp" and protocol == "icmpv6":
        port_protocol = f'{protocol}'

    if from_port == to_port and to_port == protocol:
        port_protocol = f'<strong style="color:red">All Traffic</strong>'

    rule_details = {}

    if event_name.endswith("SecurityGroupEgress"):
        # Outbound SG Rule
        rule_details = get_address(item_json, "Destination")
        rule_details["Port/Protocol"] = port_protocol
    else:
        # InBound SG Rule
        rule_details = get_address(item_json, "Source")
        rule_details["Port/Protocol"] = port_protocol

    return rule_details


## Extract & Format the Rule Details
def sg_rule_json(sg_items, event_name):
    rules_list = []

    if type(sg_items) is dict:
        rules_list.append(get_rule_breakdown(sg_items, event_name))
    elif type(sg_items) is list:
        for one_sgrule_item in sg_items:
            rules_list.append(get_rule_breakdown(one_sgrule_item, event_name))

    return rules_list


## Format the Rule in HTML Format
def sg_rule_html_display(sg_rule):

    sg_rule_html = ''

    for one_field in sg_rule:
        sg_rule_html = sg_rule_html + f'<strong>{one_field}</strong>: {sg_rule[one_field]} <br>'

    return sg_rule_html


## Format Any JSON to HTML Format
def json_html_display(str_json):
    try:
        str_json = json.dumps(str_json, indent=2, sort_keys=True).replace(' ', '&nbsp;').replace('\n', '<br>')
    except Exception as expect_me:
        logger.error(f'Exception Converting to JSON: {str_json}')
        logger.exception(expect_me)
        return f'<code> {str_json} </code>'
    return f'<code> {str_json} </code>'


########################################### EMAIL SENDER ########################################

# Send email using an unautheticated email server.
def send_email(recipients, subject, body, content_type='text/html'):

    TO = recipients
    em = EmailMessage()

    em['To'] = TO
    em['From'] = EMAIL_FROM
    em['Subject'] = subject
    em.add_header('Content-Type',content_type)
    em.set_content(body, subtype='html')
    try:
        mailserver = smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT)
        mailserver.ehlo()
        mailserver.send_message(em)
        mailserver.close()
        logger.info(f'Successfully sent the mail to {TO}')
    except Exception as expect_me:
        logger.error(f"Failed to send mail to {TO} With Exception:")
        logger.exception(expect_me)
        logger.debug("Failed to send Email, below is the HTML Code")
        logger.debug(body)


################################# Non Formatted Message Email Sender #############################

# [Robust] Send Unformatted Email incase of challenge in JSON formatting or Some Logic or Field Exception
def send_unformatted_email(wazuh_alert, email_id_list, subject_append="Non-Formatted Message", type="json"):

    subject = f'WaZuh {ENV.upper()} | {SERVICE} | {subject_append}'
    body = wazuh_alert

    if type == "json":
        body = json.dumps(wazuh_alert, indent=2, sort_keys=True).replace(' ', '&nbsp;').replace('\n', '<br>')

    send_email(email_id_list, subject, body)

    sys.exit(0)


################################### HTML Email Formatter Functions #################################


# Build the Summary Section in HTML Table
def build_summary_html_json(summary_json, service="Event Summary"):

    summary_list = []

    if service.strip() == "" or service == "Event Summary":
        title = 'Event Summary'
    else:
        title = f'{service} Event Summary'

    for one_summary in summary_json:

        summary_list.append(f'''
            <tr>
                <td style="font-weight:bold;padding-bottom: 8px;padding-right: 4px;"> {one_summary} </td>
                <td style="padding-bottom: 8px;"> {summary_json[one_summary]} </td>
            </tr>
        ''')

    summary_html = f'''
    <!-- Event Summary -->
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
        <tbody>
            {" ".join(summary_list)}
        </tbody>
    </table>
    '''

    #return { "title": title, "html":  summary_html }
    return f'''
        <!-- Summary -->
        <tr>
            <td id="onlyforpadding_left">&nbsp;</td>
            <td id="head_name" style="font-size:24px;padding:0px 0px 0px 0px;">
            <b>{title}</b>
            </td>
            <td id="onlyforpadding_right">&nbsp;</td>
        </tr>
        <tr>
            <td id="onlyforpadding_left">&nbsp;</td>
            <td class="body_details" width="100%" style="border: solid 1px #ddd; padding:10px 10px 10px 10px;">
                {summary_html}
            </td>
            <td id="onlyforpadding_right">&nbsp;</td>
        </tr>
    '''


# Build any Flattened JSONs HTML Table
def build_detailed_html_json_sections(section_json, analysis_name="Detailed Analysis"):

    section_analysis = []

    section_json = flat_it(section_json)

    for field, description in section_json.items():
        name = field.replace("_"," ").replace("-"," - ").title();

        if name not in FIELD_EXCLUSION:

            logger.debug(f"Description: {description}, Type : {type(description)}")

            if description == {} or description == '{}' or description == [] or description == '[]':
                continue
            elif type(description) is str:
                description = "<br>".join(str(convert_to_dformat(description)).split("\n"))
            elif type(description) is dict:
                description = json.dumps(description, indent=2, sort_keys=True).replace(' ', '&nbsp;').replace('\n', '<br>')
                description = f'<code> {description} </code>'
            elif type(description) is list:
                description = json.dumps(description, indent=2, sort_keys=True).replace(' ', '&nbsp;').replace('\n', '<br>')
                description = f'<code> {description} </code>'

            section_analysis.append(
                f"""
                <tr>
                    <td style="padding:10px 10px 10px 10px;border:solid 1px #ddd">
                        <span style="font-size:16px;font-weight:bold;">{name}</span> <br>
                        {description}
                    </td>
                </tr>
                """
            )

    section_table_html = f"""
        <table width="100%" border="0" cellspacing="0" cellpadding="0">
            {" ".join(section_analysis)}
        </table>
    """

    return { "title": analysis_name, "html": section_table_html }


def build_detailed_html_json(detailed_html_json):

    detailed_html_list = []

    for one_detailed_section in detailed_html_json:
        detailed_html_list.append(
            f'''
                <tr>
                    <td id="onlyforpadding_left">&nbsp;</td>
                    <td id="head_name" style="font-size:24px;padding: 0px 0px 0px 0px;">
                    <b>{one_detailed_section['title']}</b>
                    </td>
                    <td id="onlyforpadding_right">&nbsp;</td>
                </tr>
                <tr>
                    <td id="onlyforpadding_left">&nbsp;</td>
                    <td class="body_details" style="margin: 0; padding: 0">
                        {one_detailed_section['html']}
                    </td>
                    <td id="onlyforpadding_right">&nbsp;</td>
                </tr>
            '''
        )

    return " ".join(detailed_html_list)


# Build the Final HTML Content to be Sent on Email
def build_html_email(email_builder_json):

    summary_preview = email_builder_json.get('summary_preview',"Summary in the Email")
    summary_html_json = email_builder_json['summary_html_json']
    detailed_html_json = email_builder_json['detailed_html_json']
    extra_info = email_builder_json.get('extra_info',"")

    return f"""
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html>

        <head>

        <!--[if mso]>
        <style type="text/css">
            #onlyforpadding_left {{
            padding: 0px 0px 0px 10px !important;
            }}
            #onlyforpadding_right {{
            padding: 0px 10px 0px 0px !important;
            }}
            #head_name {{
            padding: 10px 0px 10px 0px !important;
            }}
        </style>
        <![endif]-->

        </head>

        <body style="background-color:#e2e1e0;font-family: Open Sans, sans-serif;font-size:100%;font-weight:400;line-height:1.4;color:#000;">
            <div style="display:none!important;mso-hide:all;">{summary_preview}</div>
            <table class="emailTable" id="emailIdTable" align="center" style="
                background-color:#fff;
                border-spacing: 10px;
                -webkit-border-radius:3px;
                -moz-border-radius:3px;
                border-radius:3px;
                -webkit-box-shadow:0 1px 3px rgba(0,0,0,.12),0 1px 2px rgba(0,0,0,.24);
                -moz-box-shadow:0 1px 3px rgba(0,0,0,.12),0 1px 2px rgba(0,0,0,.24);
                box-shadow:0 1px 3px rgba(0,0,0,.12),0 1px 2px rgba(0,0,0,.24);
                border-top: solid 10px red;
                width:100%;
                max-width: 900px;
            ">
                <tbody>
                    {summary_html_json}
                    {extra_info}
                    {detailed_html_json}
                </tbody>
                <tfooter>
                    <tr>
                        <td id="onlyforpadding_left">&nbsp;</td>
                        <td style="font-size:14px;padding:20px 0px 10px 0px;">
                            <b style="display:block;margin:0 0 10px 0;">Regards</b>
                            {FROM_TEAM} <br>
                            <b>Email:</b> {FROM_TEAM_EMAIL}
                        </td>
                        <td id="onlyforpadding_right">&nbsp;</td>
                    </tr>
                </tfooter>
            </table>
        </body>

    </html>
    """





################################ Event Analysis BreakDown Functions ################################


# GuardDuty Events
def process_guardduty_event(wazuh_alert_json):

    # Extract issue fields
    alert_level = wazuh_alert_json['rule']['level']
    ruleid = wazuh_alert_json['rule']['id']
    rule_description = wazuh_alert_json['rule']['description']

    aws_guardduty_json = wazuh_alert_json['data']['aws']

    findings_id = aws_guardduty_json['id']

    aws_region = aws_guardduty_json['region']

    guardduty_title = aws_guardduty_json['title']
    guardduty_description = aws_guardduty_json['description']

    severity_type = aws_guardduty_json['type']
    severity_level = aws_guardduty_json['severity']

    resource = aws_guardduty_json['resource']
    resourcetype = aws_guardduty_json['resource']['resourceType']

    service = aws_guardduty_json['service']
    event_firstseen = convert_to_dformat(service['eventFirstSeen'])
    event_lastseen = convert_to_dformat(service['eventLastSeen'])
    count = service['count']
    action_type = aws_guardduty_json['service']['action']['actionType']
    network_direction = None

    # Create Subject [subject]
    subject = f'WaZuh {ENV.upper()} | {SERVICE} | {severity_type} | ActionType: {action_type} | Severity: {severity_level} | {aws_region.upper()}'

    # Create Summary Preview [summary_preview]
    if action_type == "NETWORK_CONNECTION":
        network_direction = aws_guardduty_json['service']['action']['networkConnectionAction']['connectionDirection']
        summary_preview = f'{action_type}: {network_direction} | {guardduty_title}'
    else:
        summary_preview = f'{action_type} | {guardduty_title}'

    #Tracker URL
    dashboard_url = f'''https://{aws_region}.console.aws.amazon.com/guardduty/home?region={aws_region}#/findings?macros=current&fId={findings_id}'''

    # Create Summary [summary_json]
    summary_json = {
        "WaZuh": f'Id: {ruleid} / Level: {alert_level}',
        "Description" : guardduty_description,
        "FirstSeen": event_firstseen,
        "LastSeen": event_lastseen,
        "Count": count,
        "Findings": f'<a href={dashboard_url}> Go to GuardDuty </a>'
    }

    if resource.get("instanceDetails"):
        if resource.get("instanceDetails").get("tags"):
            tags_list = resource.get("instanceDetails").get("tags")

            if type(tags_list) is dict:
                if tags_list["key"] == "Name":
                    summary_json["Instance"] = f'{tags_list.get("value")} / {resource["instanceDetails"]["instanceId"]}'
                else:
                    summary_json["Instance"] = f'{resource["instanceDetails"]["instanceId"]}'
            elif type(tags_list) is list:
                for one_tag in tags_list:
                    if one_tag["key"] == "Name":
                        summary_json["Instance"] = f'{one_tag.get("value")} / {resource["instanceDetails"]["instanceId"]}'
                        break;
                    else:
                        summary_json["Instance"] = f'{resource["instanceDetails"]["instanceId"]}'
            else:
                summary_json["Instance"] = f'{resource["instanceDetails"]["instanceId"]}'

    detailed_html_json_sections= []
    resource_analysis = build_detailed_html_json_sections(section_json=resource, analysis_name="Resource Detailed Analysis")
    serivce_analysis = build_detailed_html_json_sections(section_json=service, analysis_name="Service Detailed Analysis")

    detailed_html_json_sections.append(resource_analysis)
    detailed_html_json_sections.append(serivce_analysis)

    detailed_html_json = build_detailed_html_json(detailed_html_json_sections)

    summary_html_json = build_summary_html_json(summary_json)

    email_builder_json= {
        "summary_preview": summary_preview,
        "summary_html_json": summary_html_json,
        "detailed_html_json": detailed_html_json
    }

    body = build_html_email(email_builder_json)

    return subject, body


# FIM - Syscheck Events
def process_syscheck_event(wazuh_alert_json):

    FILTER_EXCLUSION = [
        "Syscheck - Diff",
        "Id",
        "Agent - Id",
        "Rule - Mail",
        "Rule - Id",
        "Rule - Pci Dss",
        "Rule - Gpg13",
        "Rule - Gdpr",
        "Rule - Hipaa",
        "Rule - Nist 800 53",
        "Rule - Tsc",
        "Full Log"
    ]

    # Extract issue fields
    timestamp = convert_to_dformat(wazuh_alert_json.get('timestamp', ''))
    wazuh_event_id = convert_to_dformat(wazuh_alert_json.get('id', ''))


    alert_level = wazuh_alert_json['rule']['level']
    ruleid = wazuh_alert_json['rule']['id']
    rule_description = wazuh_alert_json['rule']['description']
    firedtimes = wazuh_alert_json['rule']['firedtimes']

    agent_details = wazuh_alert_json['agent']
    agent_id = agent_details['id']
    agent_name = agent_details['name']
    agent_ip = agent_details.get('ip','')

    syscheck = wazuh_alert_json["syscheck"]

    syscheck_event_type = syscheck['event']
    syscheck_mode = syscheck.get('mode', "No Mode Provided in Alert")

    syscheck_file = syscheck["path"]

    # { "dir": _dir, "file": _file, "core_dir": core_dir, "path": path }
    path_details = get_dir_and_file(syscheck_file)

    # Create Subject [subject]
    subject = f'WaZuh {ENV.upper()} | {SERVICE} | Source: {agent_name}/{agent_ip} | File: {path_details["file"]} | Core Dir: {path_details["core_dir"]}'

    # Create Audit Block
    syscheck_audit = ""
    if syscheck.get("audit"):
        audit_json = syscheck.get("audit")
        syscheck_audit = format_syscheck_audit(audit_json)
    else:
        syscheck_audit = format_syscheck_audit({})

    # Create Summary Preview [summary_preview]
    if syscheck_audit != "":
        summary_preview = f'{rule_description}'
    else:
        summary_preview = f'{rule_description}'

    #Tracker URL
    dashboard_url = f'''{WAZUH_HOST}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-30d,to:now))&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'wazuh-alerts-*',key:id,negate:!f,params:(query:'{wazuh_event_id}'),type:phrase),query:(match_phrase:(id:'1689520423.21456415')))),index:'wazuh-alerts-*',interval:auto,query:(language:kuery,query:''),sort:!())'''

    # Create Summary [summary_json]
    summary_json = {
        "File Detected": syscheck_file,
        "WaZuh": f'Id: {ruleid} / Level: {alert_level}',
        "Agent/Node name": f"{agent_name} (id={agent_id}) / {agent_ip}",
        "Event Time": timestamp,
        "Event Type": syscheck_event_type.title(),
        "Event Mode" : syscheck_mode.title(),
        "Fired Times" : firedtimes,
        "WaZuh Discover": f'''<a href={dashboard_url}> Go to WaZuh Discover </a>'''
    }

    if syscheck.get('diff'):
        # Basic
        #summary_json["Changes Made"] = syscheck.get('diff')
        # For Security
        summary_json["Changes Made"] = html.escape(syscheck.get('diff')).replace('\n', '<br/>')



    detailed_html_json_sections= []

    full_log = {
        "full_log": wazuh_alert_json["full_log"]
    }

    fulllog_analysis = build_detailed_html_json_sections(section_json=full_log, analysis_name="Full Log Detailed Analysis")

    filtered_json = filter_json(wazuh_alert_json, FILTER_EXCLUSION)

    all_analysis = build_detailed_html_json_sections(section_json=filtered_json, analysis_name="Detailed Analysis")

    detailed_html_json_sections.append(fulllog_analysis)
    detailed_html_json_sections.append(all_analysis)

    detailed_html_json = build_detailed_html_json(detailed_html_json_sections)

    summary_html_json = build_summary_html_json(summary_json)

    email_builder_json= {
        "summary_preview": summary_preview,
        "summary_html_json": summary_html_json,
        "detailed_html_json": detailed_html_json,
        "extra_info": syscheck_audit
    }

    body = build_html_email(email_builder_json)

    return subject, body


# Generic - Event
def process_generic_event(wazuh_alert_json):

    FILTER_EXCLUSION = [
        "Syscheck - Diff",
        "Id",
        "Agent - Id",
        "Rule - Mail",
        "Rule - Id",
        "Rule - Pci Dss",
        "Rule - Gpg13",
        "Rule - Gdpr",
        "Rule - Hipaa",
        "Rule - Nist 800 53",
        "Rule - Tsc",
        "Full Log",
        "Timestamp",
        "Rule - Level",
        "Rule - Description",
        "Rule - Firedtimes",
        "Agent - Name",
        "Agent - Ip"
    ]

    # Extract issue fields
    timestamp = convert_to_dformat(wazuh_alert_json.get('timestamp', ''))
    wazuh_event_id = convert_to_dformat(wazuh_alert_json.get('id', ''))


    alert_level = wazuh_alert_json['rule']['level']
    ruleid = wazuh_alert_json['rule']['id']
    rule_description = wazuh_alert_json['rule']['description']
    firedtimes = wazuh_alert_json['rule']['firedtimes']

    agent_details = wazuh_alert_json['agent']
    agent_id = agent_details['id']
    agent_name = agent_details['name']
    agent_ip = agent_details.get('ip','n/a')

    alert_type = "Unknown"

    try:
        if wazuh_alert_json.get("decoder"):
            alert_type = wazuh_alert_json.get("decoder").get("name")
        else:
            if wazuh_alert_json.get("rule").get("groups"):
                alert_type = ",".join(wazuh_alert_json.get("rule").get("groups"))
    except Exception as expect_me:
        logger.error(f'Cannot Get Decoder or Groups Details')
        logger.exception(expect_me)


    # Create Subject [subject]
    subject = f'WaZuh {ENV.upper()} | {SERVICE} | Source: {agent_name}/{agent_ip}'

    # New Format for Subject
    subject = f'WaZuh {ENV.upper()} | Level {alert_level} | {agent_name}/{agent_ip} | Type: {alert_type} | {rule_description}'

    # Create Summary Preview [summary_preview]
    summary_preview = f'{rule_description}'

    #Tracker URL
    dashboard_url = f'''{WAZUH_HOST}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-30d,to:now))&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'wazuh-alerts-*',key:id,negate:!f,params:(query:'{wazuh_event_id}'),type:phrase),query:(match_phrase:(id:'1689520423.21456415')))),index:'wazuh-alerts-*',interval:auto,query:(language:kuery,query:''),sort:!())'''

    # Create Summary [summary_json]
    summary_json = {
        "Description": rule_description,
        "WaZuh": f'Id: {ruleid} / Level: {alert_level}',
        "Agent/Node name": f"{agent_name} (id={agent_id}) / {agent_ip}",
        "Event Time": timestamp,
        "Fired Times" : firedtimes,
        "WaZuh Discover": f'''<a href={dashboard_url}> Go to WaZuh Discover </a>'''
    }

    detailed_html_json_sections= []

    wazuh_full_log = wazuh_alert_json.get("full_log")

    if wazuh_full_log:

        full_log = {
            "full_log": wazuh_full_log
        }

        if wazuh_alert_json.get("data"):
            if wazuh_alert_json.get("data").get("srcip"):

                attacker_ip = wazuh_alert_json.get("data").get("srcip")

                full_log["Attacker IP / Source IP"] = attacker_ip

                cdb_whitelist = get_cdb_whitelist()

                for one_whitelisted_ip in cdb_whitelist:
                    if one_whitelisted_ip in attacker_ip:
                        logger.warning(f"IP [{attacker_ip}] is whitelisted Skipping Email Sending")
                        sys.exit(1)

            if wazuh_alert_json.get("data").get("srcip2"):
                full_log["Attacker IP / Source IP"] = full_log["Attacker IP / Source IP"] + " | " + wazuh_alert_json.get("data").get("srcip2")

        fulllog_analysis = build_detailed_html_json_sections(section_json=full_log, analysis_name="Full Log Detailed Analysis")
        detailed_html_json_sections.append(fulllog_analysis)

    # NEW

    filtered_json = filter_json(wazuh_alert_json, FILTER_EXCLUSION)

    all_analysis = build_detailed_html_json_sections(section_json=filtered_json, analysis_name="Detailed Analysis")

    # OLD
    #all_analysis = build_detailed_html_json_sections(section_json=wazuh_alert_json, analysis_name="Detailed Analysis")

    detailed_html_json_sections.append(all_analysis)

    detailed_html_json = build_detailed_html_json(detailed_html_json_sections)

    summary_html_json = build_summary_html_json(summary_json)

    email_builder_json= {
        "summary_preview": summary_preview,
        "summary_html_json": summary_html_json,
        "detailed_html_json": detailed_html_json,
    }

    body = build_html_email(email_builder_json)

    return subject, body


# SecurityGroups - Events
def process_securitygroups_event(wazuh_alert_json):

    ## Security Group Events Naming
    security_groups_event = {
        "CreateSecurityGroup": "Created a New SG",
        "DeleteSecurityGroup": "Deleted an Existing SG",
        "AuthorizeSecurityGroupIngress": "Added Inbound Rule",
        "AuthorizeSecurityGroupEgress": "Added  Outbound Rule",
        "RevokeSecurityGroupIngress": "Deleted Inbound Rule",
        "RevokeSecurityGroupEgress": "Deleted Outbound Rule",
        "ModifySecurityGroupRules": "Modified an Existing SG Rule",
        "ModifyNetworkInterfaceAttribute": "Change an Instance's SG Assignment"
    }

    aws_securitygroups_json = wazuh_alert_json['data']['aws']

    ## Event Related Details
    event_name = aws_securitygroups_json['eventName']
    event_region = aws_securitygroups_json['awsRegion']
    source_ip = aws_securitygroups_json['sourceIPAddress']
    event_time = convert_to_dformat(aws_securitygroups_json['eventTime'])
    aws_account_id = aws_securitygroups_json['aws_account_id']
    event_id = aws_securitygroups_json['eventID']

    # AWS Rule Action
    rules_action = security_groups_event[event_name].split(' ')[0]

    ## AWS CloudTrail Tracker URL
    aws_cloudtrail_url = f'''https://{event_region}.console.aws.amazon.com/cloudtrail/home?region={event_region}#/events/{event_id}'''

    ## Fetch, Create User Info from AWS UserIdentity
    user_identity = aws_securitygroups_json['userIdentity']
    user_details = get_useridentity(user_identity)
    user_info = f'{user_details["Type"]} / {user_details["Name"]}'
    user_info_full = f'{user_details["Name"]} / {user_details["Type"]}'
    if user_details["Role"]:
        user_info_full = f'{user_details["Name"]} / {user_details["Type"]} / {user_details["Role"]}'
    user_action = f'{security_groups_event[event_name]}'

    ## Initialize Subject and Summary Preview & Summary JSON
    subject = ""
    summary_preview = ""

    account_name = AWS_ACCOUNT_NAMES.get(aws_account_id, aws_account_id)

    # Create Summary [summary_json]
    summary_json = {
        "AWS": f'{account_name} / {event_region}',
        "Event Time": event_time,
        "User / Type / Role": f'{user_info_full}',
        "Initiated": f'Action by IP: {source_ip}',
        "CloudTrail": f'''<a href={aws_cloudtrail_url}> Go to CloudTrail Event </a>'''
    }

    ## Identify Event Success or Failed
    if aws_securitygroups_json.get('errorMessage'):
        # Critical Event - Failed to Change SG Group
        error_message = aws_securitygroups_json.get("errorMessage")
        # Create Subject [subject]
        subject = f'WaZuh {ENV.upper()} | {SERVICE} | Failed: {error_message} | {event_name} | {user_info}'

        # Create Summary Preview [summary_preview]
        summary_preview = f'Failed: {error_message} | {user_info} initiated {user_action}'

        # Build Summary
        summary_json["Error Code"] = aws_securitygroups_json.get("errorCode", "No Error Code")
        summary_json["Error Description"] = aws_securitygroups_json.get("errorMessage", "No Error Message")

    else:
        # Create Subject [subject]
        subject = f'WaZuh {ENV.upper()} | {SERVICE} | {event_name} | {user_info}'

        # Create Summary Preview [summary_preview]
        summary_preview = f'{user_info} Successfully initiated {user_action}'

    # Extracting Request and Response Params of the Event
    request_params = aws_securitygroups_json.get("requestParameters")
    response_params = aws_securitygroups_json.get("responseElements", {})

    if event_name == "CreateSecurityGroup":
        vpc_id = request_params["vpcId"]
        sg_id = response_params.get("groupId")
        sg_name = f'{request_params["groupName"]}'
        if sg_id:
            sg_name = f'{request_params["groupName"]} / {sg_id}'
        sg_description = request_params["groupDescription"]

        summary_json["Alert Description"] =  f'{user_action} / VPC: {vpc_id}'
        summary_json["SG Name"] = sg_name
        summary_json["SG Details"] = sg_description

    elif event_name == "DeleteSecurityGroup":
        sg_id = request_params.get("groupId")
        summary_json["Alert Description"] =  f'{user_action} / SG: {sg_id}'
        summary_json["SG Id"] = sg_id

    elif event_name == "AuthorizeSecurityGroupIngress" or event_name == "AuthorizeSecurityGroupEgress" or event_name == "RevokeSecurityGroupIngress" or event_name == "RevokeSecurityGroupEgress":

        sg_id = request_params.get("groupId")

        sg_rule_count = 1
        request_items = aws_securitygroups_json["requestParameters"]["ipPermissions"]["items"]

        if type(request_items) is list:
            sg_rule_count = len(request_items)

        sg_rule_list = sg_rule_json(request_items, event_name)

        # Create Summary [summary_json]
        summary_json["Alert Description"] =  f'{user_action} / SG: {sg_id}'
        summary_json[f"No of Rules {rules_action}"] =  sg_rule_count

        count = 1
        for one_sg_rule in sg_rule_list:
            summary_json[f'{rules_action} Rule {count}'] = sg_rule_html_display(one_sg_rule)
            count = count + 1


    elif event_name == "ModifySecurityGroupRules":
        sg_id = request_params["ModifySecurityGroupRulesRequest"]["GroupId"]
        sg_rule_modified = request_params["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]

        summary_json["Alert Description"] =  f'{user_action} / SG: {sg_id}'
        summary_json[f'{rules_action}'] = sg_rule_html_display(sg_rule_modified)

    elif event_name == "ModifyNetworkInterfaceAttribute":
        is_sg_related_change = request_params.get("groupSet")

        if not is_sg_related_change:
            analysis_info = "ENI Event is not related to SG Related Change.. Skipping event"
            logger.warning(analysis_info)
            sys.exit(analysis_info)

        sg_list = request_params["groupSet"]["items"]
        eni_id = request_params["networkInterfaceId"]

        sg_id_list = []

        if type(sg_list) is dict:
            sg_id_list.append(sg_list["groupId"])
        elif type(sg_list) is list:
            for one_sg in sg_list:
                sg_id_list.append(one_sg["groupId"])
        else:
            sg_id_list = sg_list

        eni_change = {
            "Network / ENI Id": eni_id,
            "SG List": " , ".join(sg_id_list)
        }

        summary_json["Alert Description"] =  f'{user_action} / ENI: {eni_id}'
        summary_json[f'{rules_action}'] = sg_rule_html_display(eni_change)

    detailed_html_json_sections= []

    if aws_securitygroups_json.get("requestParameters"):
        request_parameters_analysis = build_detailed_html_json_sections(section_json=aws_securitygroups_json.get("requestParameters"), analysis_name="Request Parameters Detailed Analysis")
        detailed_html_json_sections.append(request_parameters_analysis)

    if aws_securitygroups_json.get("responseElements"):
        response_elements_analysis = build_detailed_html_json_sections(section_json=aws_securitygroups_json.get("responseElements"), analysis_name="Response Elements Detailed Analysis")
        detailed_html_json_sections.append(response_elements_analysis)

    detailed_html_json = build_detailed_html_json(detailed_html_json_sections)

    summary_html_json = build_summary_html_json(summary_json, SERVICE)

    email_builder_json= {
        "summary_preview": summary_preview,
        "summary_html_json": summary_html_json,
        "detailed_html_json": detailed_html_json,
    }

    body = build_html_email(email_builder_json)

    return subject, body


# CloudTrail - Events
def process_cloudtrail_event(wazuh_alert_json):
    logger.info(f'No Current Handler for process_cloudtrail_event, Therefore sending it to Generic Event Handler')
    return process_generic_event(wazuh_alert_json)



#########################################################################################################

# Main Function
def main():

    file_content = ""
    wazuh_alert_json = {}
    email_id_list = []

    # Check the Input Constraint
    if len(sys.argv) < 4:
        logger.error(f'Received Inputs ({len(sys.argv)}) do not Qualify the Requirements (min 4) ')
        logger.error(f'Received Input: {sys.argv=}')
        sys.exit(1)

    logger.info(f'Received Input: {sys.argv=}')

    # Read Input from WaZuh Integrations

    # Type of Alert // api_key
    global SERVICE
    SERVICE = sys.argv[2]

    if SERVICE.strip() == "":
        SERVICE = "WaZuh"


    # Email ID List // hook_url
    for one_email in sys.argv[3].split(","):
        email_id_list.append(one_email.strip())

    # Read the alert file // Input by WaZuh Dynamic
    try:
        with open(sys.argv[1]) as f_object:
            file_content = f_object.read()
            wazuh_alert_json = json.loads(file_content)

    except Exception as expect_me:
        logger.error(f'Exception reading & fetching WaZuh Alert JSON: {file_content}')
        logger.exception(expect_me)
        send_unformatted_email(file_content, email_id_list, "Non-Formatted Message | Exception Parsing, Check Integration Logs", type="text")

    logger.info(f'Alert JSON received from WaZuh: {wazuh_alert_json=}')
    logger.info(f'Alert TYPE received from WaZuh: {SERVICE=}')
    logger.info(f'Email ID List received from WaZuh: {email_id_list=}')

    subject = "No Subject"
    body = "No Body"

    try:
        if SERVICE.upper() == "GUARDDUTY":
            logger.info(f'Service: {SERVICE}, Handler: process_guardduty_event')
            subject, body = process_guardduty_event(wazuh_alert_json)
        elif SERVICE.upper() == "FIM":
            logger.info(f'Service: {SERVICE}, Handler: process_syscheck_event')
            subject, body = process_syscheck_event(wazuh_alert_json)
        elif SERVICE.upper() == "SECURITYGROUPS":
            logger.info(f'Service: {SERVICE}, Handler: process_securitygroups_event')
            subject, body = process_securitygroups_event(wazuh_alert_json)
        elif SERVICE.upper() == "CLOUDTRAIL":
            logger.info(f'Service: {SERVICE}, Handler: process_cloudtrail_event')
            subject, body = process_cloudtrail_event(wazuh_alert_json)
        elif SERVICE.upper() == "GENERIC":
            SERVICE = "WaZuh"
            logger.info(f'Service: {SERVICE}, Handler: process_generic_event')
            subject, body = process_generic_event(wazuh_alert_json)
        else:
            SERVICE = "WaZuh"
            logger.info(f'Service: {SERVICE}, Handler: process_generic_event (No Known SERVICE Provided)')
            subject, body = process_generic_event(wazuh_alert_json)

    except Exception as expect_me:

        logger.error("Failed to Process WaZuh Alert JSON")
        logger.exception(expect_me)
        send_unformatted_email(wazuh_alert_json, email_id_list, "Non-Formatted Message | Failed JSON Fields")

    send_email(email_id_list, subject, body)

    sys.exit(0)


main()