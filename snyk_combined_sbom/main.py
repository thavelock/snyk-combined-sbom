"""Main module
"""

import typer
from rich import print
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing_extensions import Annotated

from snyk_combined_sbom import snyk, utils

app = typer.Typer(add_completion=False)
state = {'verbose': False}

@app.command('create')
def create_data_structure(
        org_id:
            Annotated[
                str,
                typer.Argument(help='ID of Organization in Snyk for generating SBOMs')],
        snyk_token:
            Annotated[
                str,
                typer.Option(
                    help='Snyk API token, or set as environment variable',
                    envvar='SNYK_TOKEN')],
        origin: str = typer.Option(
                    default='any',
                    help='Project origin')):

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=False
    ) as progress:
        # Retrieve all targets from Snyk Org
        done = progress.add_task(description="Getting all targets from Org...", total=1)
        targets = snyk.get_all_targets_in_org(org_id, snyk_token, origin)
        progress.update(done, description="All targets retrieved from Org \u2713", completed=1)

        # Retrieve all projects from Snyk Org
        done = progress.add_task(description="Getting all projects from Org...", total=1)
        projects = snyk.get_all_projects_in_org(org_id, snyk_token, origin)
        progress.update(done, description="All projects retrieved from Org \u2713", completed=1)

        # Map projects to a target
        done = progress.add_task(description="Mapping projects to targets", total=1)
        mapped_targets = utils.map_projects_to_targets(projects, targets)
        progress.update(done, description="All projects mapped \u2713", completed=1)

        # Create directory structure to store individual project SBOMs
        done = progress.add_task(description="Creating output directories", total=1)
        utils.create_target_directories(mapped_targets)
        progress.update(done, description="Output directories created \u2713", completed=1)

        # Retrieve the SBOMs for each project and store it in the correct directory
        done = progress.add_task(description="Retrieve SBOMs for projects", total=1)
        utils.retrieve_sboms_from_targets(mapped_targets, org_id, snyk_token, progress=progress, progress_id=done)
        progress.update(done, description="SBOMs retrieved \u2713", completed=1)

@app.command('clean')
def clean_directory_structure():
    utils.remove_output_directory()

@app.callback()
def main(verbose: bool = False):
    if verbose:
        state['verbose'] = True

def run():
    """The main entry point for the CLI
    """
    app()
