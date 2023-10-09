from django.urls import path,include
from . import views

urlpatterns = [
    path('',views.SignupPage,name='signup'),
    path('signup/',views.SignupPage,name='signup'),
    path('login/',views.LoginPage,name='login'),
    path('home/',views.home,name='home'),
    path('logout/',views.LogoutPage,name='logout'),
    path('about/',views.AboutPage,name='about'),
]
