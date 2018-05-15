# Generated by Django 2.0.4 on 2018-05-15 17:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0019_update_help_text'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='request',
            options={'ordering': ['-id']},
        ),
        migrations.AddField(
            model_name='template',
            name='description',
            field=models.TextField(blank=True, help_text='Description of the certificate that will be displayed to the users so that they understand the purpose of this template.'),
        ),
    ]