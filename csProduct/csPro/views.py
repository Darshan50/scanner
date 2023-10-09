from django.shortcuts import render,HttpResponse,redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import FileResponse
import os

# Create your views here.

from .models import urlInput 
from .forms import urlInput 
import validators
from . import scan

@login_required(login_url='login')
def home(request):
    if request.method == 'POST':
        start_url = request.POST.get("url")
        if not start_url.startswith("http://"):
            start_url="http://"+start_url
        scan.start(start_url)
        return render(request, 'result.html')
    else:
        return render(request, 'home.html')

def SignupPage(request):
    if request.method=='POST':
        uname=request.POST.get('username')
        email=request.POST.get('email')
        pass1=request.POST.get('password1')
        pass2=request.POST.get('password2')
        if User.objects.filter(email=email).exists():
            raise ValidationError("An user with this email already exists!")
        else:
            email = email 
        if pass1!=pass2:
            return HttpResponse("Your password and confrom password are not Same!!")
        else:

            my_user=User.objects.create_user(uname,email,pass1)
            my_user.save()
            return redirect('login')
        
    return render (request,'signup.html')

def LoginPage(request):
    if request.method=='POST':
        username=request.POST.get('username')
        pass1=request.POST.get('pass')
        user=authenticate(request,username=username,password=pass1)
        if user is not None:
            login(request,user)
            return redirect('home')
        else:
            return HttpResponse ("Username or Password is incorrect!!!")

    return render (request,'login.html')

def LogoutPage(request):
    logout(request)
    return redirect('login')

# def download_report(request):
#     # base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) 
#     # filename = 'myfile2.html'
#     # filepath = base_dir + 'templates/myfile2.html' + filename
#     # thefile = filepath
#     # filename = os.path.basename(thefile)
#     # chunk_size = 8192
#     # response = StreamingHttpResponse(FileWrapper(open(thefile,'rb'),chunk_size),concert_type=mimetypes)
#     # return 
#     source_file_path = "D:\CS Internship\csProduct\\templates\myfile2.html" 
#     destination_folder_path = "D:\Cyber Internship Report" 
#     shutil.copy(source_file_path, destination_folder_path)
#     return render(request,'myfile2.html')

def AboutPage(request):

    return render(request, 'about.html')
