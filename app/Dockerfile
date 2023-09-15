###########
# BUILDER #
###########

# Pull official base image
FROM python:3.11-alpine as builder

# Set work directory
WORKDIR /usr/src/app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install dependencies
RUN apk update
RUN apk add curl gettext
# Install psycopg2 dependencies
RUN apk add postgresql-dev gcc python3-dev musl-dev

RUN pip install --upgrade pip

# Install project dependencies
COPY ./requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

########
# BASE #
########

# Pull official base image
FROM python:3.11-alpine as base

# Install dependencies
RUN apk update
RUN apk add curl gettext

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip

# Set work directory
WORKDIR /

COPY --from=builder /usr/src/app/wheels /wheels
RUN pip install --no-cache /wheels/*

RUN mkdir -p /logs

# Create directory for the app user and create the app user
ENV HOME=/home/app
RUN mkdir -p ${HOME}
RUN addgroup -S app && adduser -s /bin/ash -S app -G app

WORKDIR ${HOME}

# Not used in the app, but just for reference
COPY --from=builder /usr/src/app/requirements.txt .

COPY ./entrypoint.sh ${HOME}/entrypoint.sh
RUN sed -i 's/\r$//g' ${HOME}/entrypoint.sh
RUN chmod +x ${HOME}/entrypoint.sh

RUN chown -R app:app $HOME
RUN chown -R app:app /logs

USER app

ENTRYPOINT [ "/home/app/entrypoint.sh" ]

#########
# FINAL #
#########

# Pull official base image
FROM base as final

USER root

# Create the appropriate directories
ENV APP_HOME=${HOME}/web
RUN mkdir -p $APP_HOME/staticfiles
RUN mkdir -p $APP_HOME/mediafiles

# Copy project
COPY ./src $APP_HOME

# Chown all the files to the app user
RUN chown -R app:app $APP_HOME

# Change to the app user
USER app

########
# LINT #
########

# FROM base as lint

# WORKDIR /tmp

# RUN pip install flake8==5.0.4
# COPY . .
# # E501: Line too long
# # F401: Module imported but unused
# RUN flake8 --ignore=E501,F401 .
