from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField

from .managers import CustomUserManager

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_("email address"), unique=True)
    organisation = models.ForeignKey('Organisation', on_delete=models.SET_NULL, null=True, blank=True,to_field='name')
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email



class organisation(models.Model):
    name = models.CharField(max_length=30, unique=True)
    description = models.CharField(max_length=300)
    owner = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='owned_organisations', to_field='email')
    members = ArrayField(models.IntegerField(), default=list)
    comment = models.CharField(max_length=300)
    
    def __str__(self):
        return self.name
    
    def is_owner(self, user):
        return user == self.owner

class Requestjoin(models.Model):
    request_status = models.CharField(max_length=20, null=False, default='In Progress')
    message = models.CharField(max_length=300)
    organisation = models.ForeignKey('organisation', on_delete=models.CASCADE, related_name='join_requests',to_field='name')
    requested_by = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='requested_join_requests',to_field='email')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.request_status

    def save(self, *args, **kwargs):
        if not self.pk:
            self.request_status = 'In Progress'
        return super(Requestjoin, self).save(*args, **kwargs)

class Invitation(models.Model):
    request_status = models.CharField(max_length=20, null=False, default='In Progress')
    organisation = models.ForeignKey('organisation', on_delete=models.CASCADE, to_field='name')
    guest = models.ForeignKey('CustomUser', on_delete=models.CASCADE,to_field='email')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.request_status

    def save(self, *args, **kwargs):
        if not self.pk:
            self.request_status = 'Waiting'
        return super(Invitation, self).save(*args, **kwargs)

