# Generated by Django 5.0.2 on 2024-03-03 13:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0007_support_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='todo',
            name='id',
            field=models.PositiveIntegerField(primary_key=True, serialize=False),
        ),
    ]