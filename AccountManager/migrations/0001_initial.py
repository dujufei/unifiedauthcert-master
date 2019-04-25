# Generated by Django 2.2 on 2019-04-17 11:59

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='RoleTable',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(max_length=30, verbose_name='角色')),
                ('creator', models.CharField(max_length=30, verbose_name='创建者')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='创建时间')),
            ],
            options={
                'db_table': 'role',
            },
        ),
        migrations.CreateModel(
            name='UserTable',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=30, verbose_name='员工姓名')),
                ('sex', models.CharField(choices=[('0', '女'), ('1', '男')], max_length=10, verbose_name='员工性别')),
                ('username', models.CharField(max_length=32, verbose_name='用户名')),
                ('password', models.CharField(max_length=32, verbose_name='密码')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='创建时间')),
                ('login_time', models.DateTimeField(auto_now=True, verbose_name='最近登录时间')),
                ('role', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='AccountManager.RoleTable')),
            ],
            options={
                'db_table': 'user',
            },
        ),
        migrations.CreateModel(
            name='PlatForm',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=32, verbose_name='平台名称')),
                ('is_bind', models.CharField(choices=[('0', '解除'), ('1', '绑定')], max_length=10, verbose_name='是否绑定平台')),
                ('platform', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='AccountManager.RoleTable')),
            ],
            options={
                'db_table': 'platform',
            },
        ),
    ]