"""Collection of helper functions to call Snyk APIs
"""

import json
import time

import requests
import rich

from snyk_combined_sbom.constants import (SNYK_REST_API_BASE_URL,
                                          SNYK_REST_API_VERSION,
                                          SNYK_API_TIMEOUT_DEFAULT,
                                          DEFAULT_SBOM_FORMAT)


def get_all_projects_in_org(org_id, snyk_token, origin=None):
    """Retrieve all projects in a Snyk Organization

    Args:
        org_id (string): ID of Snyk Organization
        snyk_token (string): Snyk API token
    """

    projects = []

    headers = {
        'Authorization': f'token {snyk_token}'
    }

    if origin is None or origin == 'any' :
        url = f'{SNYK_REST_API_BASE_URL}/orgs/{org_id}/projects?version={SNYK_REST_API_VERSION}&limit=100'
    else:
        url = f'{SNYK_REST_API_BASE_URL}/orgs/{org_id}/projects?version={SNYK_REST_API_VERSION}&limit=100&origins={origin}'

    while True:
        response = requests.request(
            'GET',
            url,
            headers=headers,
            timeout=SNYK_API_TIMEOUT_DEFAULT)

        response_json = json.loads(response.content)

        if 'data' in response_json:
            projects = projects + response_json['data']

        if 'next' not in response_json['links'] or response_json['links']['next'] == '':
            break
        url = f"{SNYK_REST_API_BASE_URL}/{response_json['links']['next']}"
        time.sleep(0.1)

    return projects


def get_all_targets_in_org(org_id, snyk_token, origin=None):
    """Retrieve all targets in a Snyk Organization

    Args:
        org_id (string): ID of Snyk Organization
        snyk_token (string): Snyk API token
    """

    targets = []

    headers = {
        'Authorization': f'token {snyk_token}'
    }

    if origin is None or origin == 'any' :
        url = f'{SNYK_REST_API_BASE_URL}/orgs/{org_id}/targets?version={SNYK_REST_API_VERSION}'
    else:
        url = f'{SNYK_REST_API_BASE_URL}/orgs/{org_id}/targets?version={SNYK_REST_API_VERSION}&origin={origin}'

    while True:
        response = requests.request(
            'GET',
            url,
            headers=headers,
            timeout=60)

        response_json = json.loads(response.content)

        if 'data' in response_json:
            targets = targets + response_json['data']

        if 'next' not in response_json['links'] or response_json['links']['next'] == '':
            break
        url = f"{SNYK_REST_API_BASE_URL}/{response_json['links']['next']}"
        time.sleep(0.1)

    return targets

def get_sbom_for_project(org_id, project_id, snyk_token, sbom_format=DEFAULT_SBOM_FORMAT):
    """Retrieve an SBOM for a given project

    Args:
        org_id (string): ID of Snyk Organization
        project_id (string): ID of Snyk Project
        snyk_token (string): Snyk API token
        sbom_format (string, optional): Format for SBOM to returned as. Defaults to DEFAULT_SBOM_FORMAT.

    Returns:
        string: SBOM string, or None if error retrieving SBOM
    """

    headers = {
        'Authorization': f'token {snyk_token}'
    }

    url = f'{SNYK_REST_API_BASE_URL}/orgs/{org_id}/projects/{project_id}/sbom?version={SNYK_REST_API_VERSION}&format={sbom_format}'

    response = requests.request(
            'GET',
            url,
            headers=headers,
            timeout=60)

    if (response.status_code != 200):
        if (response.status_code == 404):
            response_json = json.loads(response.content)

            errors = ''

            for error in response_json['errors']:
                errors += f"{error['code']}, "

            print(f"\u26A0 Could not get SBOM for project {project_id}, errors: {errors.strip(', ')}")

        return None

    return response.text
