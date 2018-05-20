# Generated by Django 2.0.4 on 2018-05-16 23:42

from django.db import migrations, models
import webca.web.fields
import webca.web.validators


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0022_template_key_sizes'),
    ]

    operations = [
        migrations.AddField(
            model_name='template',
            name='min_bits_dsa',
            field=models.PositiveSmallIntegerField(default=1024, help_text='Minimum DSA key size', validators=[webca.web.validators.valid_key_size_number], verbose_name='DSA Key size'),
        ),
        migrations.AddField(
            model_name='template',
            name='min_bits_ec',
            field=models.PositiveSmallIntegerField(default=256, help_text='Minimum Elliptic Curves (EC) key size', validators=[webca.web.validators.valid_key_size_number], verbose_name='EC Key size'),
        ),
        migrations.AlterField(
            model_name='template',
            name='key_usage',
            field=webca.web.fields.KeyUsageField(choices=[('digitalSignature', 'digitalSignature'), ('nonRepudiation', 'nonRepudiation'), ('keyEncipherment', 'keyEncipherment'), ('dataEncipherment', 'dataEncipherment'), ('keyAgreement', 'keyAgreement'), ('keyCertSign', 'keyCertSign'), ('cRLSign', 'cRLSign'), ('encipherOnly', 'encipherOnly'), ('decipherOnly', 'decipherOnly')], default='digitalSignature', help_text='This list defines the allowed algorithms used by the public key of the certificates.', max_length=250, verbose_name='KeyUsage'),
        ),
    ]