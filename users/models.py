import re
from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

# Password validation function
def validate_password_strength(password):
    if not password:
        return
    
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character.')

# Custom User Model
class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'phone_number']
    
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def save(self, *args, **kwargs):
        # Only validate password strength, don't hash it again
        if self.password and not self.password.startswith(('pbkdf2_sha256$', 'bcrypt$', 'argon2')):
            validate_password_strength(self.password)
            # Let Django's create_user handle the hashing
        super().save(*args, **kwargs)

# Newsletter Subscriber Model
class NewsletterSubscriber(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(auto_now_add=True)

# FIR Model
class FIR(models.Model):
    CRIME_TYPES = [
        ('Cyber', 'Cyber'),
        ('Physical', 'Physical'),
    ]
    
    CRIME_CATEGORIES = [
        ('Robbery', 'Robbery'),
        ('Molestation', 'Molestation'),
        ('Fraud', 'Fraud'),
        ('Other', 'Other'),
    ]
    
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    crime_type = models.CharField(max_length=10, choices=CRIME_TYPES)
    crime_name = models.CharField(max_length=20, choices=CRIME_CATEGORIES)
    description = models.TextField()
    name = models.CharField(max_length=100)
    email = models.EmailField()
    citizenship = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"FIR {self.id} - {self.crime_type} - {self.crime_category}"
