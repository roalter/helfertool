FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

USER root

WORKDIR /root

RUN apt-get update -qqy && apt-get install -qqy gettext python3-venv python3-pip libldap-2.5-0 libldap2-dev libsasl2-dev libssl-dev libpq-dev build-essential pkg-config ldap-utils libldap2-dev libsasl2-dev libmariadb-dev libpq-dev libmagic1 texlive-latex-extra texlive-plain-generic texlive-fonts-recommended texlive-lang-german


ENV PATH "/root/bin/:$PATH"

COPY src/requirements* /root/
COPY build-scripts/ /root/bin/

RUN python3 -m pip install --upgrade pip --no-cache-dir && python3 -m pip install --no-cache-dir -r /root/requirements.txt -r /root/requirements_prod.txt
RUN freeze-python.sh /root/env/

FROM ubuntu:22.04

ARG VERSION=0.0
ARG DEBIAN_FRONTEND=noninteractive

LABEL maintainer="Foo"
LABEL description="Foo"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8
ENV DJANGO_SETTINGS_MODULE="helfertool.settings_container"
ENV HELFERTOOL_CONFIG_FILE="/config/helfertool.yaml"
ENV PATH "/helfertool/scripts/:$PATH"

USER root

RUN apt-get update -qqy && apt-get install -qqy python3 libldap-2.5-0 ca-certificates nano netcat python-is-python3 && rm -fR /var/cache/apt

COPY --from=builder /root/env/ /usr/local/

WORKDIR /helfertool

COPY ./src/ /helfertool/
COPY ./scripts/ /helfertool/scripts/

RUN chmod 755 /helfertool/scripts/*

ENTRYPOINT ["/helfertool/scripts/entrypoint"]
CMD ["start"]


