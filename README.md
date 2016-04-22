# minion-http-code-checker-plugin
A plugin that check the http code of a target for Minion

Installation
------------

It assumes that you have already Minion installed (https://github.com/mozilla/minion)
- Clone the project with `git clone https://github.com/glestel/minion-http-code-checker-plugin.git`
- If needed load the virtualenv with `source {minion-directory}/minion/env/bin/activate`
- Then run in the minion-http-code-checker-plugin directory : `python setup.py develop`

Example of plan
---------------

```
[
  {
    "configuration": {
      "report_dir": "/tmp/artifacts/",
      "expected_code": 403,
      "user-agent": "WordPress/2.1.1"
    },
    "description": "Used to check the http response of a target",
    "plugin_name": "minion.plugins.http_code_checker.HTTPCodeCheckerPlugin"
  }
]
```

The list of available options are :
- `report_dir` : directory were the logging file will be written. Default is `/tmp/artifacts`
- `expected_code` : HTTP code expected when the GET request will be made against the target. Default is `200`
- `user-agent` : user agent used with the request
