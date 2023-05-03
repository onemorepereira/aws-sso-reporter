import boto3
import csv
import json
import string
import time
import unicodedata

from datetime import datetime

"""
list_accounts

Lists all AWS accounts assigned to the user.

Parameters:
-- None
Returns:
-- List[Dictionary]: account_list (a list of accounts each described by a dictionary with keys 'name' and 'id')
"""
def list_accounts():
    account_list = []
    org = boto3.client('organizations')
    paginator = org.get_paginator('list_accounts')
    page_iterator = paginator.paginate()

    for page in page_iterator:
        for acct in page['Accounts']:
            # only add active accounts
            if acct['Status'] == 'ACTIVE':
                account_list.append({'name': acct['Name'], 'id': acct['Id']})

    return account_list

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

    response = client.list_permission_sets(InstanceArn=ssoInstanceArn)

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
list_account_assignments

Lists the assignee of the specified AWS account with the specified permission set.

Parameters:
-- String: ssoInstanceArn
-- String: accountId
-- String: permissionSetArn
Returns:
-- List[Dictionary]: account_assignments (a list of account assignments represented by dictionaries with the keys 'PrincipalType' and 'PrincipalId')
"""
def list_account_assignments(ssoInstanceArn, accountId, permissionSetArn):
    client = boto3.client('sso-admin')

    paginator = client.get_paginator("list_account_assignments")

    response_iterator = paginator.paginate(
        InstanceArn=ssoInstanceArn,
        AccountId=accountId,
        PermissionSetArn=permissionSetArn
    )

    account_assignments = []
    for response in response_iterator:
        for row in response['AccountAssignments']:
            # add only relevant keys to return
            account_assignments.append({'PrincipalType': row['PrincipalType'], 'PrincipalId': row['PrincipalId']})

    return account_assignments

"""
describe_user

Retrieves the user metadata and attributes from user id in an identity store to return a human friendly username.

Parameters:
-- String: userId
-- String: identityStoreId
Returns:
-- String: username (a human friendly username for the user id)
"""
def describe_user(userId, identityStoreId):
    client = boto3.client('identitystore')
    try:
        response = client.describe_user(
            IdentityStoreId=identityStoreId,
            UserId=userId
        )
       username = response['UserName']

       return username
    except Exception as e:
        print("[WARN] User was deleted while the report was running: " + str(userId))
        username = "USER-GROUP"
        return username    

"""
describe_group

Retrieves the group metadata and attributes from group id in an identity store to return a human friendly group name.

Parameters:
-- String: groupId
-- String: identityStoreId
Returns:
-- String: groupname (a human friendly groupname for the group id)
"""
def describe_group(groupId, identityStoreId):
    client = boto3.client('identitystore')
    try:
        response = client.describe_group(
            IdentityStoreId=identityStoreId,
            GroupId=groupId
        )
        groupname = response['DisplayName']
        return groupname
    except Exception as e:
        print("[WARN] Group was deleted while the report was running: " + str(groupId))
        groupname = "DELETED-GROUP"
        return groupname

"""
create_report

Creates a report of the assigned permissions on users for all accounts in an organization.

Parameters:
-- List[Dictionary]: account_list (a list of accounts each described by a dictionary with keys 'name' and 'id')
-- List[Dictionary]: sso_instance (a list of sso instances each described by a dictionary with keys 'instanceArn' and 'identityStore')
-- Dictionary: permission_sets_list (a dictionary with permission sets with key permission set name and value permission set arn)
Returns:
-- List[Dictionary]: result (a list of dictionaries with keys 'AccountID', 'AccountName', 'PermissionSet', 'ObjectName', 'ObjectType')
"""
def create_report(account_list, sso_instance, permission_sets_list, break_after=None):
    result = []

    # variables for displaying the progress of processed accounts
    length = str(len(account_list))
    i = 1

    for account in account_list:
        for permission_set in permission_sets_list.keys():
            # get all the users assigned to a permission set on the current account
            account_assignments = list_account_assignments(sso_instance['instanceArn'], account['id'], permission_sets_list[permission_set])

            # add the users and additional information to the sso report result
            for account_assignment in account_assignments:
                account_assignments_dic = {}

                # add information for all the headers
                account_assignments_dic['AccountID'] = account['id']
                account_assignments_dic['AccountName'] = account['name']
                account_assignments_dic['PermissionSet'] = permission_set
                account_assignments_dic['ObjectType'] = account_assignment['PrincipalType']

                # find human friendly name for user id if principal type is "USER"
                if account_assignments_dic['ObjectType'] == "USER":
                    username = describe_user(account_assignment['PrincipalId'], sso_instance['identityStore'])
                    account_assignments_dic['ObjectName'] = username
                # find human friendly name for group id if principal type is "GROUP"
                elif account_assignments_dic['ObjectType'] == "GROUP":
                    groupname = describe_group(account_assignment['PrincipalId'], sso_instance['identityStore'])
                    account_assignments_dic['ObjectName'] = groupname

                result.append(account_assignments_dic)

        # display the progress of processed accounts
        print(str(i) + "/" + length + " accounts done")
        i = i+1

        # debug code used for stopping after a certain amound of accounts for faster testing
        if break_after != None and i > break_after:
            break

    return result

"""
write_result_to_file

Writes a list of dictionaries to a csv file.

Parameters:
-- String: result
Returns:
-- None
Output:
-- CSV file: CSV with SSO report.
"""
def write_result_to_file(result):
    filename = 'sso_report_Account_Assignments_' + datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.csv'
    filename = clean_filename(filename)
    with open(filename, 'w', newline='') as csv_file:
        fieldnames = ['AccountID', 'AccountName', 'ObjectType', 'ObjectName', 'PermissionSet'] # The header/column names
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        for row in result:
            writer.writerow(row)

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
    account_list = list_accounts()
    sso_instance = list_existing_sso_instances()[0]
    permission_sets_list = list_permission_sets(sso_instance['instanceArn'])
    result = create_report(account_list, sso_instance, permission_sets_list)
    write_result_to_file(result)

    # print the time it took to generate the report
    end = time.time()
    print_time_taken(start, end)

main()
