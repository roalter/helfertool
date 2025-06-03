import argparse
import logging
import os

import django
import uvicorn
from gunicorn.app.base import BaseApplication


class StandaloneApplication(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {key: value for key, value in self.options.items() if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

if __name__ == '__main__':
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "helfertool.settings")

    parser = argparse.ArgumentParser(description='Django Server')
    parser.add_argument("protocol")
    parser.add_argument('-p', '--port', default=8193, type=int)
    parser.add_argument("-n", "--hostname", default="0.0.0.0", type=str)
    parser.add_argument('-d', '--debug', default=False, action='store_true')
    parser.add_argument('-s', '--settings', default=os.environ.get("DJANGO_SETTINGS_MODULE"), type=str)
    parser.add_argument('-w', '--workers', default=None, type=str)

    args = parser.parse_args()

    django.setup()
    base = os.path.dirname(__file__)

    if args.debug:
        os.environ.setdefault("DEBUG", "1")
        logging.basicConfig(level=logging.DEBUG)

    if args.protocol == "asgi":
        uvicorn.run(
            "helfertool.asgi:application",
            app_dir=base,
            host=args.hostname,
            port=args.port,
            workers=args.workers,
            lifespan="off",
            proxy_headers=True,
            date_header=True,
            server_header=True,
        )
    elif args.protocol == "wsgi":
        from helfertool.wsgi import application
        options = dict(
            bind="%s:%s" % (args.hostname, str(args.port)),
            workers=2
        )
        StandaloneApplication(application, options).run()
    else:
        from django.core.management import execute_from_command_line
        execute_from_command_line(["", "runserver", f"{args.hostname}:{args.port}"])
