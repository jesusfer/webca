# Generated by Django 2.0.4 on 2018-04-29 16:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('certstore_db', '0002_auto_20180429_1407'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificate',
            name='basic_contraints',
            field=models.CharField(default='', help_text='CA cert indication and pathlen', max_length=50),
        ),
        migrations.AlterField(
            model_name='keypair',
            name='key_type',
            field=models.CharField(choices=[('rsa', 'RSA'), ('dsa', 'DSA')], default='rsa', max_length=3),
        ),
    ]
