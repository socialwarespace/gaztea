from django.db import models


class Herriak(models.Model):
    izena_eus = models.CharField(max_length=200)
    izena_cast = models.CharField(max_length=200)
    probintzia = models.CharField(max_length=200)
    biztanleak = models.IntegerField()
    azalera = models.FloatField()
