# python.exe .\manage.py runserver --settings webca.ca_admin.settings
python.exe .\manage.py runsslserver 443 --settings webca.ca_admin.settings --certificate certs/www.webca.net.cer --key certs/www.webca.net.key
