# Generated by Django 4.2.6 on 2024-02-25 19:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0005_contactus'),
    ]

    operations = [
        migrations.CreateModel(
            name='support',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('support', models.CharField(max_length=1000)),
            ],
        ),
    ]
