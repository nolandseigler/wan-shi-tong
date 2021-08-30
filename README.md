# wan-shi-tong
CVE/CPE flask project

Developed on macOS
## Requires Poetry, Bash, Docker with Compose
* [ ] Run:
```shell
poetry install
```
* [ ] Run:
```shell
./automation/run_postgres_nvd_db.sh
```
* [ ] Run:
```shell
./automation/run_prefect_server.sh
```
* [ ] Run in new terminal window:
```shell
./automation/run_prefect_agent.sh
```
* [ ] Run in new terminal window:
```shell
./automation/run_prefect_flow_registration.sh
```
* [ ] Run:
```shell
poetry run python run.py
```

View app at http://127.0.0.1:8082/
