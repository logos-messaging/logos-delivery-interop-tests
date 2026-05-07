# logos-messaging-interop-tests

Logos Messaging end‑to‑end (e2e) interoperability test framework for the [Waku v2 protocol](https://rfc.vac.dev/spec/10/). It exercises multiple clients (logos-messaging-nim, js‑waku, go‑waku…) in realistic network topologies and reports results via Allure.

## Setup & contribution

```bash
# Use sparse checkout since the repo has large history
git clone --depth=1 git@github.com:logos-messaging/logos-messaging-interop-tests.git
cd logos-messaging-interop-tests

# create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# install python dependencies + prepare git hooks
pip install -r requirements.txt
pre-commit install
```

> **Tip** – You can override any default variable defined in `src/env_vars.py` either
> • by exporting it before the `pytest` call, or
> • by creating a `.env` file at the repository root.

## Running tests locally

Run **one specific test**:

```bash
pytest -k test_unsubscribe_from_some_content_topics
```

Run **an entire test class / suite**:

```bash
pytest -k TestRelaySubscribe
```

All usual [pytest](https://docs.pytest.org/) selectors (`-k`, `-m`, `-q`, etc.) work.

Waku logs can be found in `log/docker` folder while test log can be seen either in the terminal or in the `log` folder.

## Continuous Integration (CI)

### Daily build on *nwaku\:latest*

Every day the workflow **nim\_waku\_daily.yml** triggers against the image `wakuorg/nwaku:latest`.

To launch it manually:

1. Open [https://github.com/logos-messaging/logos-messaging-interop-tests/actions/workflows/nim\_waku\_daily.yml](https://github.com/logos-messaging/logos-messaging-interop-tests/actions/workflows/nim_waku_daily.yml).
2. Click **► Run workflow**.
3. Pick the branch you want to test (defaults to `master`) and press **Run workflow**.

### On‑demand matrix against custom *logos-messaging-nim* versions

Use **interop\_tests.yml** when you need to test a PR or a historical image:

1. Open [https://github.com/logos-messaging/logos-messaging-interop-tests/actions/workflows/interop\_tests.yml](https://github.com/logos-messaging/logos-messaging-interop-tests/actions/workflows/interop_tests.yml).
2. Press **► Run workflow** and choose the branch.
3. In the *workflow inputs* field set the `nwaku_image` you want, e.g. `wakuorg/nwaku:v0.32.0`.

### Viewing the results

* When the job finishes GitHub will display an **Allure Report** link in the run summary.
* The bot also posts the same link in the **Waku / test‑reports** Discord channel.

### Updating the CI job used from *logos-messaging-nim*

In the **logos-messaging-nim** repository itself the file `.github/workflows/test_PR_image.yml` pins the interop test version to `SMOKE_TEST_STABLE`.

To update it, move the `SMOKE_TEST_STABLE` tag to point to the desired commit in `waku-interop-tests`.

## License

Licensed under either of:

* **MIT License** – see [LICENSE-MIT](https://github.com/waku-org/js-waku/blob/master/LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT)
* **Apache License 2.0** – see [LICENSE-APACHE-v2](https://github.com/waku-org/js-waku/blob/master/LICENSE-APACHE-v2) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

at your option.
