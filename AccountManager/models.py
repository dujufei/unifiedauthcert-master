from django.db import models

# Create your models here.


# 角色表
class RoleTable(models.Model):
    role = models.CharField(max_length=30, verbose_name='角色')
    creator = models.CharField(max_length=30, verbose_name='创建者')
    create_time = models.DateTimeField(verbose_name='创建时间', auto_now_add=True)
    # 创建者
    # 创建时间

    def __str__(self):
        return self.role

    class Meta:
        db_table = 'role'

# 用户表
class UserTable(models.Model):
    name = models.CharField(max_length=30, verbose_name='员工姓名')
    sex = models.CharField(max_length=10, choices=(('0', '女'), ('1', '男')), verbose_name='员工性别')
    username = models.CharField(max_length=32, verbose_name='用户名')
    password = models.CharField(max_length=32, verbose_name='密码')
    create_time = models.DateTimeField(verbose_name='创建时间', auto_now_add=True)
    login_time = models.DateTimeField(verbose_name='最近登录时间', auto_now=True)
    role = models.OneToOneField(RoleTable, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'user'

# 平台表
class PlatForm(models.Model):
    name = models.CharField(max_length=32, verbose_name='平台名称')
    is_bind = models.CharField(max_length=10, choices=(('0', '解除'), ('1', '绑定')), verbose_name='是否绑定平台')
    platform = models.ForeignKey(RoleTable, on_delete=models.CASCADE)
    def __str__(self):
        return self.name

    class Meta:
        db_table = 'platform'