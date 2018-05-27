# Run tests and generate coverage report
coverage run --source='.' manage.py test webca --settings webca.ca_ocsp.settings #--parallel=4
coverage html
coverage xml
# htmlcov/index.html
