import boto3
import csv
import json
import time
from datetime import datetime

def print_time_taken(start, end):
    elapsed_time = end - start
    elapsed_time_string = str(int(elapsed_time/60)) + " minutes and "  + str(int(elapsed_time%60)) + " seconds"
    print("The report took " + elapsed_time_string + " to generate.")

"""
describe_organization

Retrieves organization information.

Parameters:
-- None
Returns:
-- Dictionary: Organization information
"""
def describe_organization():
    client = boto3.client('organizations')
    response = client.describe_organization()
    
    return response['Organization']

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
list_users

Retrieves accounts for a specified identity store.

Parameters:
-- String: identity_store_id
Returns:
-- List[Dictionary]: Identity store user accounts
"""
def list_users(identity_store_id):
    print('retrieving accounts...', end='\t')
    client = boto3.client('identitystore')
    paginator = client.get_paginator("list_users")
    response_iterator = paginator.paginate(
        IdentityStoreId=identity_store_id
    )

    account_results = []
    for response in response_iterator:
        for account in response['Users']:
            account_dict = account.copy()
            del account_dict['Name']
            del account_dict['Emails']

            for email in account['Emails']:
                if email['Primary']:
                    account_dict['PrimaryEmail'] = email['Value']

            account_memberships = list_group_account_memberships(account['IdentityStoreId'],account['UserId'])
            account_dict['GroupMemberships'] = account_memberships

            account_results.append(account_dict)
    print('done')
    return account_results

"""
list_group_account_memberships

Retrieves the group memberships for a User account.

Parameters:
-- String: identity_store_id
-- String: user_id
Returns:
-- List[Dictionary]: User's group memberships
"""
def list_group_account_memberships(identity_store_id,user_id):
    client = boto3.client('identitystore')
    response = client.list_group_memberships_for_member(
        IdentityStoreId = identity_store_id,
        MemberId = {'UserId': user_id})
    
    return response['GroupMemberships']

"""
list_groups

Retrieves the groups for a specified identity store.

Parameters:
-- String: identity_store_id
Returns:
-- List[Dictionary]: Identity store groups
"""
def list_groups(identity_store_id):
    print('retrieving groups...', end='\t')
    client = boto3.client('identitystore')
    paginator = client.get_paginator("list_groups")
    response_iterator = paginator.paginate(
        IdentityStoreId=identity_store_id
    )

    group_results = []
    for response in response_iterator:
        for group in response['Groups']:
            group_results.append(group)
    
    print('done')
    return group_results

"""
get_logon_stats

Retrieves user earliest and most recent logon times from the past 90 days from CloudTrail 'CredentialVerification' events.

Parameters:
-- None
Returns:
-- List[Dictionary]: User account logon stats
"""
def get_logon_stats():
    print('retrieving logon stats from cloudtrail events...', end='\t')
    client = boto3.client('cloudtrail')
    paginator = client.get_paginator("lookup_events")
    lookup_attributes = [
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'CredentialVerification'
        },]
    response_iterator = paginator.paginate(
        LookupAttributes=lookup_attributes
    )

    logons_dict = {}
    for response in response_iterator:
        for event in response['Events']:

            ct_event = json.loads((event['CloudTrailEvent']))
            username = ct_event['userIdentity']['userName']
            event_time = ct_event['eventTime']
            event_time_dt = datetime.strptime(event_time,"%Y-%m-%dT%H:%M:%SZ")
            credential_verification = ct_event['serviceEventDetails']['CredentialVerification']

            if username in logons_dict:
                earliest_success = logons_dict[username]['EarliestSuccess']
                latest_success = logons_dict[username]['LatestSuccess']
                count_success = logons_dict[username]['CountSuccess']
                earliest_failure = logons_dict[username]['EarliestFailure']
                latest_failure = logons_dict[username]['LatestFailure']
                count_failure = logons_dict[username]['CountFailure']
            else:
                earliest_success = latest_success = None
                count_success = 0
                earliest_failure = latest_failure = None
                count_failure = 0

            if credential_verification == 'Success':
                count_success += 1
                if earliest_success:
                    if event_time_dt < datetime.strptime(earliest_success,"%Y-%m-%dT%H:%M:%SZ"):
                        earliest_success = event_time
                else:
                    earliest_success = event_time
                if latest_success:
                    if event_time_dt > datetime.strptime(latest_success,"%Y-%m-%dT%H:%M:%SZ"):
                        latest_success = event_time
                else:
                    latest_success = event_time

            if credential_verification == 'Failure':
                count_failure += 1
                if earliest_failure:
                    if event_time_dt < datetime.strptime(earliest_failure,"%Y-%m-%dT%H:%M:%SZ"):
                        earliest_failure = event_time
                else:
                    earliest_failure = event_time
                if latest_failure:
                    if event_time_dt > datetime.strptime(latest_failure,"%Y-%m-%dT%H:%M:%SZ"):
                        latest_failure = event_time
                else:
                    latest_failure = event_time

            if latest_success is not None:
                days_since_success = (datetime.utcnow() - \
                    datetime.strptime(latest_success,"%Y-%m-%dT%H:%M:%SZ")).days
            else:
                days_since_success = None

            logons_dict[username] = {
                'UserName':username,
                'EarliestSuccess':earliest_success,
                'LatestSuccess':latest_success,
                'DaysSinceSuccess':days_since_success,
                'CountSuccess':count_success,
                'EarliestFailure':earliest_failure,
                'LatestFailure':latest_failure,
                'CountFailure':count_failure
                }

    logons_output = []
    for user in logons_dict.values():
        logons_output.append(user)

    print('done')
    return logons_output

"""
create_credential_report

Creates a credential report for all user accounts in an Identity Store.

Parameters:
-- Dictionary: sso_instance (sso instance 'instanceArn' and 'identityStore')
-- List[Dictionary]: accounts (Identity store user accounts)
-- List[Dictionary]: groups (Identity store groups)
-- List[Dictionary]: recent_logon_activity (User account logon stats)
Returns:
-- None
Output:
-- CSV file: CSV with credential report
"""
def create_credential_report(organization, sso_instance, accounts, groups, recent_logon_activity):
    print('generating report...')

    filename = 'sso_report_Account_Credential_' + datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.csv'
    fieldnames = ['AwsAccountId', 'SsoInstanceARN', 'IdentityStoreId', 'UserId', 'UserName', \
        'DisplayName', 'PrimaryEmail', 'GroupMembershipIds', 'GroupMembershipNames', 'CountSuccess', \
            'DaysSinceSuccess', 'LatestSuccess', 'EarliestSuccess', 'CountFailure', 'LatestFailure', 'EarliestFailure']

    with open(filename, 'w', newline='') as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for account in accounts:
            # accounts
            row = account.copy()

            # organization
            row['AwsAccountId'] = organization['MasterAccountId']

            # sso_instance
            row['SsoInstanceARN'] = sso_instance['instanceArn']

            # groups
            group_names = []
            group_ids = []
            del row['GroupMemberships']
            for group_member in account['GroupMemberships']:
                group_lookup = [group for group in groups if group['GroupId'] == group_member['GroupId']][0]
                group_names.append(group_lookup['DisplayName'])
                group_ids.append(group_lookup['GroupId'])
            row['GroupMembershipNames'] = ', '.join(group_names)
            row['GroupMembershipIds'] = ', '.join(group_ids)

            # logon stats
            users_logon_activity = [user_activity for user_activity in recent_logon_activity if user_activity['UserName'] == account['UserName']]
            if users_logon_activity:
                users_logon_activity = users_logon_activity[0]
            row.update(users_logon_activity)

            writer.writerow(row)

"""
main

Output:
-- CSV file: CSV with SSO credential report.
"""
def main():
    start = time.time()

    organization = describe_organization()
    sso_instance = list_existing_sso_instances()[0]
    accounts = list_users(sso_instance['identityStore'])
    groups = list_groups(sso_instance['identityStore'])
    logon_stats = get_logon_stats()

    create_credential_report(organization, sso_instance, accounts, groups, logon_stats)

    end = time.time()
    print_time_taken(start, end)

main()