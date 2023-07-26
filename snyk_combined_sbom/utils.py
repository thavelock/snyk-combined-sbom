import os
import shutil

from snyk_combined_sbom import snyk

from rich import print

OUTPUT_DIR = './output'

def map_projects_to_targets(projects, targets):

    mapped_targets = {}

    for target in targets:
        mapped_targets[target['id']] = {
            'displayName': target['attributes']['displayName'],
            'directoryName': f"{target['id']}-{remove_special_chars(target['attributes']['displayName'])}",
            'projects': []
        }

    for project in projects:
        if project['attributes']['type'] not in ['sast', 'cloudformationconfig', 'helmconfig', 'k8sconfig', 'terraformconfig']:
            if project['relationships']['target']['data']['id'] in mapped_targets:
                mapped_targets[project['relationships']['target']['data']['id']]['projects'].append({
                    'id': project['id'],
                    'name': project['attributes']['name'],
                    'type': project['attributes']['type'],
                    'sbomFileName': f"{project['id']}-{remove_special_chars(project['attributes']['name'])}.json"
                })

    return mapped_targets

def create_target_directories(mapped_targets):
    try:
        os.mkdir(OUTPUT_DIR)

    except FileExistsError:
        print(f'{OUTPUT_DIR} already exists')

    for target in mapped_targets.values():
        try:
            os.mkdir(f"{OUTPUT_DIR}/{target['directoryName']}")
        except FileExistsError:
            print(f"{OUTPUT_DIR}/{target['directoryName']} already exists")

def retrieve_sboms_from_targets(mapped_targets, org_id, snyk_token, progress=None, progress_id=-1):

    for target in mapped_targets.values():
        for project in target['projects']:

            filename = f"{OUTPUT_DIR}/{target['directoryName']}/{project['sbomFileName']}"

            if not os.path.isfile(filename):

                project_sbom = snyk.get_sbom_for_project(org_id, project['id'], snyk_token)

                if progress is not None:
                    progress.update(progress_id, description=f"Creating SBOM: {filename}", advance=1.0)

                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(project_sbom)
                    f.close()

            elif progress is not None:
                progress.update(progress_id, description=f"SBOM Exists: {filename}", advance=1.0)

def remove_output_directory():
    try:
        shutil.rmtree(OUTPUT_DIR)
    except FileNotFoundError:
        print(f"{OUTPUT_DIR} doesn't exist")
    except OSError:
        print(f"Couldn't remove {OUTPUT_DIR}")

def remove_special_chars(text):
    return text.replace('/', '_').replace('.', '_').replace(':', '_').replace('(', '_').replace(')', '_')

def number_of_projects(mapped_targets):
    count = 0
    for target in mapped_targets.values():
        count += len(target['projects'])

    return count
