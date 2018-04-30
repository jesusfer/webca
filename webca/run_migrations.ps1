python manage.py makemigrations
$v = Read-Host -Prompt "Apply migrations?"
if ($v)
{
    python manage.py migrate admin
    python manage.py migrate auth
    python manage.py migrate contenttypes
    python manage.py migrate sessions
    python manage.py migrate web
    python manage.py migrate certstore_db --database certstore_db
}