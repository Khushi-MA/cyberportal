import re
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from .models import CustomUser, NewsletterSubscriber, validate_password_strength, FIR # Import FIR model
from django.core.exceptions import ValidationError
import logging

logger = logging.getLogger(__name__)

def home(request):
    if request.user.is_authenticated:
        welcome_message = f"Welcome, {request.user.username}"
    else:
        welcome_message = "Welcome"
    
    context = {
        'user': request.user,
        'is_authenticated': request.user.is_authenticated,
        'welcome_message': welcome_message,
    }
    logger.info(f"Home view accessed by user: {request.user}")
    return render(request, 'home.html', context)

def user_login(request):
    if request.user.is_authenticated:
        return redirect('home')
    
    form = AuthenticationForm()
    context = {'form': form}
    
    if request.method == 'POST':
        email = request.POST.get('username')
        password = request.POST.get('password')
        
        # Basic email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            context['email_error'] = 'Please enter a valid email address'
            return render(request, 'user_login.html', context)
        
        # Try to authenticate
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            login(request, user)
            logger.info(f"User {email} authenticated successfully")
            return redirect('home')
        else:
            # If authentication fails, add error to context
            logger.error(f"Authentication failed for email: {email}")
            context['error'] = 'Invalid email or password'
            return render(request, 'user_login.html', context)
    
    return render(request, 'user_login.html', context)

def user_register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        password = request.POST.get('password')
        user = CustomUser.objects.create_user(username=username, email=email, phone_number=phone_number, password=password)
        login(request, user)
        return redirect('home')
    return render(request, 'user_register.html')

def subscribe(request):
    if request.method == 'GET':
        email = request.GET.get('subscribe-email')
        if email:
            NewsletterSubscriber.objects.create(email=email)
    return redirect('home')

def contact(request):
    if request.method == 'POST':
        first_name = request.POST.get('first-name')
        last_name = request.POST.get('last-name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        # Handle the contact form submission (e.g., save to database, send email, etc.)
        # For now, just redirect to home
        return redirect('home')
    return render(request, 'contact.html')

def logout_view(request):
    logout(request)
    return redirect('home')

@login_required(login_url='user_login')
def register_fir(request):
    if request.method == 'POST':
        # Handle form submission
        crime_type = request.POST.get('crimeType')
        crime_name = request.POST.get('crimeName')
        description = request.POST.get('crimeDescription')
        name = request.POST.get('donation-name')
        email = request.POST.get('donation-email')
        citizenship = request.POST.get('DonationPayment')
        
        # Create and save the FIR object
        fir = FIR(
            user=request.user,
            crime_type=crime_type,
            crime_name=crime_name,
            description=description,
            name=name,
            email=email,
            citizenship=citizenship
        )
        fir.save()
        
        # Redirect after successful submission
        return redirect('home')
        
    return render(request, 'register_fir.html')

