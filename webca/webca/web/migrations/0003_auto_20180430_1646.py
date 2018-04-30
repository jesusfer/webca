# Generated by Django 2.0.4 on 2018-04-30 14:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0002_template_auto_sign'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='certificate',
            name='template',
        ),
        migrations.AddField(
            model_name='request',
            name='template',
            field=models.ForeignKey(default=0, on_delete=django.db.models.deletion.DO_NOTHING, to='web.Template'),
            preserve_default=False,
        ),
    ]
