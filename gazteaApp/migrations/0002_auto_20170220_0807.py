# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-02-20 08:07
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gazteaApp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='herriak',
            name='azalera',
            field=models.FloatField(default=0.0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='herriak',
            name='biztanleak',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]