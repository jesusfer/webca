#!/bin/sh

echo Host: $HOSTNAME

echo "Waiting for PostgreSQL..."
while ! nc -z $SQL_HOST $SQL_PORT; do
  sleep 0.1
done

export PYTHONPATH=/home/app/web:$PYTHONPATH

case $1 in
  webca)
    echo Starting WebCA
    gunicorn core.wsgi:application --bind 0.0.0.0:8000 --workers 4 --threads 2
  ;;
  all)
    echo Starting all services
    # Start Web CA
    celery -A core worker -E -f $LOGS_DIR/$HOSTNAME-celery.log &
    # Start Admin
    celery -A core beat -f $LOGS_DIR/$HOSTNAME-celery-beat.log &
    # Start OCSP
    celery -A core flower &
    # Wait for any process to exit
    wait -n
    # Exit with status of process that exited first
    exit $?
  ;;
  *)
    echo Custom command
    # Search for env vars in the cmd to execute
    # Mainly used for celery
    # exec "$@"
    exec $(echo "$@" | envsubst)
  ;;
esac
