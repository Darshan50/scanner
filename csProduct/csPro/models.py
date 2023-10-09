from django.db import models

# Create your models here.

class csPro(models.Model):
    title = models.CharField(max_length=100)

    def __str__(self):
        return self.title

class urlInput(models.Model):
    url = models.CharField(max_length=100)
    def __str__(self):
        return self.url
