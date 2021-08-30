import prefect

from env_vars import prefect_project_name


def ensure_project_exists():
    client = prefect.Client()

    print("Ensuring prefect project named '{prefect_project_name}'exists.")

    try:
        client.create_project(project_name=prefect_project_name)
        print(f"{prefect_project_name} has been created.")
    except prefect.utilities.exceptions.ClientError as ce:
        if "Uniqueness violation" in str(ce):
            print(f"Project: {prefect_project_name} exists")
        else:
            raise ce
