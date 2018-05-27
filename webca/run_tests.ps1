# Run tests and generate coverage report
coverage run --source='.' manage.py test webca #--parallel=4
coverage html
# htmlcov/index.html
