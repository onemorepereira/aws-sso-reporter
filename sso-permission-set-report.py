import boto3
import csv
import json
import string
import time
import unicodedata

from datetime import datetime

"""
list_existing_sso_instances

Lists the SSO instances that the caller has access to.

Parameters:
-- None
Returns:
-- List[Dictionary]: sso_instance_list (a list of sso instances each described by a dictionary with keys 'instanceArn' and 'identityStore')
"""
def list_existing_sso_instances():
    client = boto3.client('sso-admin')

    sso_instance_list = []
    response = client.list_instances()
    for sso_instance in response['Instances']:
        # add only relevant keys to return
        sso_instance_list.append({'instanceArn': sso_instance["InstanceArn"], 'identityStore': sso_instance["IdentityStoreId"]})

    return sso_instance_list

"""
list_permission_sets

Lists the PermissionSet in an SSO instance.

Parameters:
-- String: ssoInstanceArn
Returns:
-- Dictionary: perm_set_dict (a dictionary with permission sets with key permission set name and value permission set arn)
"""
def list_permission_sets(ssoInstanceArn):
    client = boto3.client('sso-admin')

    perm_set_dict = {}
    response = client.list_permission_sets(InstanceArn=ssoInstanceArn, MaxResults=100)
    results = response["PermissionSets"]

    while "NextToken" in response: 
        response = client.list_permission_sets(InstanceArn=ssoInstanceArn, NextToken=response["NextToken"])
        results.extend(response["PermissionSets"]) 

    for permission_set in results:
        # get the name of the permission set from the arn
        perm_description = client.describe_permission_set(InstanceArn=ssoInstanceArn,PermissionSetArn=permission_set)
        # key: permission set name, value: permission set arn
        perm_set_dict[perm_description["PermissionSet"]["Name"]] = permission_set

    return perm_set_dict

"""
create_report

Creates a report of the assigned permissions on users for all accounts in an organization.

Parameters:
-- List[Dictionary]: sso_instance (a list of sso instances each described by a dictionary with keys 'instanceArn' and 'identityStore')
-- Dictionary: permission_sets_list (a dictionary with permission sets with key permission set name and value permission set arn)
Returns:
-- None
Output:
-- CSV file: CSV with permissions set report
-- Json files: Json files with inline policies attached to permission sets if any
"""
def create_report(sso_instance, permission_sets_list, break_after=None):
    client = boto3.client('sso-admin')

    # variables for displaying the progress of processed accounts
    length = str(len(permission_sets_list))
    i = 1

    # loop through permission sets and write details to file
    filename = 'sso_report_Managed_Policies_per_Permission_Set_' + datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.csv'
    filename = clean_filename(filename)
    with open(filename, 'w', newline='') as output_file:
        output_file.write("PermissionSet,ManagedPolicyName,ManagedPolicyARN\n")
        for permission_set in permission_sets_list.keys():
            managed_policies = client.list_managed_policies_in_permission_set(InstanceArn=sso_instance['instanceArn'],PermissionSetArn=permission_sets_list[permission_set])


            # create managed policy csv file if there are any managed policies attached to the permission set
            if(len(managed_policies['AttachedManagedPolicies']) > 0):
                for m_policy in managed_policies["AttachedManagedPolicies"]:
                    output_file.write(permission_set + "," + m_policy["Name"] + "," + m_policy["Arn"] + "\n")


            # create inline policy json file if there is an inline policy attached to the permission set
            inline_policy = client.get_inline_policy_for_permission_set(InstanceArn=sso_instance['instanceArn'],PermissionSetArn=permission_sets_list[permission_set])
            if(inline_policy["InlinePolicy"] != ''):
                json_filename = 'sso_report_InlinePolicy_for_' + permission_set + '_' + datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.json'
                json_filename = clean_filename(json_filename)
                with open(json_filename, 'w', newline='') as json_output_file:
                    json_object = json.loads(inline_policy["InlinePolicy"])
                    json_output_file.write(json.dumps(json_object, indent=2))
                    json_output_file.close()

            # display the progress of processed accounts
            print(str(i) + "/" + length + " permission sets done")
            i = i+1

            # debug code used for stopping after a certain amount of accounts for faster testing
            if break_after != None and i > break_after:
                break

def print_time_taken(start, end):
    elapsed_time = end - start
    elapsed_time_string = str(int(elapsed_time/60)) + " minutes and "  + str(int(elapsed_time%60)) + " seconds"
    print("The report took " + elapsed_time_string + " to generate.")

def clean_filename(filename, replace=' ', char_limit=255):
    #allowed chars
    valid_filename_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)

    # replace spaces
    for r in replace:
        filename = filename.replace(r,'_')

    # keep only valid ascii chars
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()

    # keep only whitelisted chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in valid_filename_chars)
    if len(cleaned_filename)>char_limit:
        print("Warning, filename truncated because it was over {}. Filenames may no longer be unique".format(char_limit))
    return cleaned_filename[:char_limit]

"""
main

Output:
-- CSV file: CSV with SSO report.
"""
def main():
    start = time.time()
    sso_instance = list_existing_sso_instances()[0]
    permission_sets_list = list_permission_sets(sso_instance['instanceArn'])
    create_report(sso_instance, permission_sets_list)

    # print the time it took to generate the report
    end = time.time()
    print_time_taken(start, end)

main()
