# LOG Collector

Developed by: CodefilterPH | Euge

LOG Collector is a Django application for local Nginx access-log collection,
security incidents, API access, WebSocket updates, Celery processing, and
read-only connections to other LOG Collector installations. CrowdSec connection
management is included in the distribution.

Install with `pip install codefilterph-logcollector`. Add `log_collector` and
`crowdsec_integration` to `INSTALLED_APPS`, mount `log_collector.urls`, and run
migrations. Nginx file access, ASGI, a channel layer, and Celery services are
configured by the host project; installing the wheel does not provision them.

### Dashboard access

The dashboard requires a signed-in Django user who belongs to the `DATA_CENTER`
group. A superuser must also belong to that group. Opening the hosting entity's
Manage page and changing collector configuration additionally requires
`is_superuser=True`. The collector uses its own hosting entity and does not
require the host project to have an `Organization` model.

Mount `log_collector.urls` before root-level slug routes such as
`path("<slug:slug>/", ...)`; otherwise a catch-all route can capture
`/log-collector/` before the collector receives the request.

The developer guides are installed in `log_collector/docs/` inside the Python
package and are also available in the source repository:

- [Installation](https://github.com/codefilterPH/logcollector/blob/main/log_collector/docs/installation.md)
- [Configuration](https://github.com/codefilterPH/logcollector/blob/main/log_collector/docs/configuration.md)
- [API integration](https://github.com/codefilterPH/logcollector/blob/main/log_collector/docs/api.md)
- [Operations](https://github.com/codefilterPH/logcollector/blob/main/log_collector/docs/operations-guide.md)

The app title defaults to **LOG Collector**. A Django superuser can set the
displayed title and shared theme on the hosting entity Manage page. The developer
credit is fixed in the application and cannot be edited through its settings.

License: [MIT](LICENSE).

Release owner: [first-release account setup](https://github.com/codefilterPH/logcollector/blob/main/RELEASE_SETUP.md).
