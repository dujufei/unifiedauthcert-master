from django.urls import path
from AccountManager import views

app_name = 'account'

urlpatterns = [
    path('login/', views.LoginUser.as_view(), name='login'),
    path('add/', views.AddUser.as_view(), name='add'),
    path('show/', views.ShowUser.as_view(), name='show'),
    path('update/', views.UpdateUser.as_view(), name='update'),
    path('delete/', views.DeleteUser.as_view(), name='delete'),
    path('show_platform/', views.ShowPlat.as_view(), name='show_platform'),
    path('bind_auth/', views.AuthView.as_view(), name='platform'),

    # show all plat
    path('show_all_plat/', views.ShowAllPlat.as_view(), name='show_all_plat'),
    # path('show_all_plat_test/', views.ShowAllPlatTest.as_view(), name='show_all_plat_test'),

]
