# Run tests and generate coverage report
coverage run --source='.' webca/manage.py test webca --settings webca.ca_ocsp.settings #--parallel=4
coverage html
coverage xml
# htmlcov/index.html
# python .\manage.py test webca.ca_ocsp --settings webca.ca_ocsp.settings
