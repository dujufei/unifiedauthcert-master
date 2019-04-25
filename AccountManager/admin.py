from django.contrib import admin

# Register your models here.
from AccountManager.models import UserTable, RoleTable

admin.site.register(UserTable)
admin.site.register(RoleTable)
