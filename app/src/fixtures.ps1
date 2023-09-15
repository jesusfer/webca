python .\manage.py dumpdata -e sessions -e contenttypes -e admin -e auth.Permission -o .\webca\tests\fixtures\initial.json --indent 2
python .\manage.py dumpdata config -o .\webca\tests\fixtures\config.json --indent 2
python .\manage.py dumpdata certstore_db --settings webca.ca_ocsp.settings --database certstore_db -o .\webca\tests\fixtures\certstore_db.json --indent 2
