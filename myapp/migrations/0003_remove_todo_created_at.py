# Generated by Django 4.2.6 on 2024-02-01 20:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0002_todo_created_at'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='todo',
            name='created_at',
        ),
    ]
