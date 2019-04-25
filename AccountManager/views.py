import hashlib
from UnifiedAuthCert.config import *
from .models import UserTable, RoleTable ,PlatForm
import logging
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
import datetime
logger = logging.getLogger('AuthCert.error')


# jwt加密
def JwtEncode(username, password):
    encode_jwt = jwt.encode({'username': username, 'password': password}, SALT,
                            algorithm='HS256')
    str_token = str(encode_jwt, encoding='utf-8')
    return str_token

# jwt解密
def JwtDecode(encode_jwt):
    decode_payload = jwt.decode(encode_jwt, SALT, algorithms=['HS256'])
    return decode_payload

# Md5加密密码
def PwdMd5(pwd):
    pwd_salt = pwd + SALT
    password = hashlib.md5(pwd_salt.encode())
    password = password.hexdigest()
    return password

class LoginUser(APIView):
    """
    用户登录
    """

    def get(self, request, format=None):
        resp = {
            'code': 100,
            'message': 'this is GET method'
        }
        logger.info('this is a LoginUser GET method')
        return Response(resp)


    def post(self, request, format=None):
        try:
            username = request.data.get('username')
            pwd = request.data.get('password')
            password = PwdMd5(pwd)
            user = UserTable.objects.filter(username=username, password=password)
            if len(user):
                user[0].login_time = str(datetime.datetime.now())
                user[0].save()
                token = JwtEncode(username, password)
                resp = {
                    'code': 100,
                    'message': 'success',
                    'token': token,
                    'username': username
                }
                logger.info('login sucess')
            else:
                resp = {
                    'code': 101,
                    'message': 'username 、 password Error',
                }
                logger.error('username and password Error')
        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.info(str(e))
        return Response(resp)

class AddUser(APIView):
    """
    增加用户
    """
    def get(self, request, format=None):
        resp = {
            'code': 100,
            'message': 'this is GET method'
        }
        logger.info('this is a AddUser GET method')
        return Response(resp)

    def post(self, request, format=None):
        try:
            role = request.data.get('role')
            token = request.META.get('HTTP_AUTHORIZATION')
            creator = JwtDecode(token)['username']
            name = request.data.get('name')
            sex = request.data.get('sex')
            username = request.data.get('username')
            username = username + '@haxitag.com'
            password = request.data.get('password')
            if not all([role, creator, name, sex, username, password]):
                logger.error('Parameter omission')
                resp = {
                    'code': 101,
                    'message': '参数不完整',
                }
            elif len(UserTable.objects.filter(username=username)):
                resp = {
                    'code': 101,
                    'message': '用户名已存在'
                }
                logger.error('the user name already exists')
            else:
                try:
                    # 对密码进行MD5加密
                    password = PwdMd5(password)
                    # 保存用户数据
                    Role = RoleTable()
                    Role.role = role
                    Role.creator = creator
                    Role.save()
                    User = UserTable()
                    User.role = Role
                    User.name = name
                    User.sex = sex
                    User.username = username
                    User.password = password
                    User.save()
                    logger.info('add user success')
                    resp = {
                        'code': 100,
                        'message': '增加用户成功',
                    }
                except Exception as e:
                    logger.error(str(e))
                    resp = {
                        'code': 101,
                        'message': str(e),
                    }
        except Exception as e:
            logger.info(str(e))
            resp = {
                'code': 101,
                'message': str(e)
            }
        return Response(resp)


class ShowUser(APIView):
    """
    展示用户信息,通过用户名密码来查询其它信息
    """
    def get(self, request, format=None):
        try:
            Users = UserTable.objects.all()
            users_list = []
            for user in Users:
                id = user.id
                name = user.name
                sex = user.sex
                username = user.username
                create_time = user.create_time.strftime('%Y-%m-%d')
                login_time = user.login_time.strftime('%Y-%m-%d %H:%M:%S')
                role = user.role.role
                creator = user.role.creator
                temp_dict = {
                    'id': id,
                    'name': name,
                    'sex': sex,
                    'username': username,
                    'role': role,
                    'creator': creator,
                    'create_time': create_time,
                    'login_time': login_time
                }
                users_list.append(temp_dict)
            resp = {
                'code': 100,
                'message': 'success',
                'data': users_list
            }
            logger.info('show user success')
        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.error(str(e))
        return Response(resp)

class UpdateUser(APIView):
    """
        修改用户的信息，目前只支持修改自己的信息
    """
    def post(self, request, format=None):
        try:
            id = request.data.get('id')
            data = UserTable.objects.get(id=id)
            name = data.name
            sex = data.sex
            username = data.username
            passwrod = data.password
            role_id = data.role_id
            name = request.data.get('name', name)
            sex = request.data.get('sex', sex)
            username = request.data.get('username', username)
            passwrod = request.data.get('password', passwrod)
            role = request.data.get('role', role_id)
            Role = RoleTable.objects.get(id=role_id)
            Role.role = role
            Role.save()
            data.name = name
            data.sex = sex
            data.username = username
            pwd = PwdMd5(passwrod)
            data.password = pwd
            data.save()
            resp = {
                'code': 100,
                'message': '修改成功'
            }
            logger.info('update success')
        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.error(str(e))
        return Response(resp)


class DeleteUser(APIView):
    """
    需要判断是否有权限才能执行删除
    """
    # 需要判断是否有权限才能执行删除

    def get(self, request, format=None):
        try:
            id = request.GET.get('id')
            # data = UserTable.objects.get(id=id)
            # role_id = data.role_id
            # RoleTable.objects.get(id=role_id).delete()
            # data.delete()
            role = UserTable.objects.get(id=id).role.role
            if role == '管理者':
                data = UserTable.objects.get(id=id)
                role_id = data.role_id
                RoleTable.objects.get(id=role_id).delete()
                data.delete()
                resp = {
                    'code': 100,
                    'message': 'success'
                }
                logger.info('delete success')
            else:
                resp = {
                    'code': 101,
                    'message': '对不起，您不是管理员，不能执行删除操作'
                }
        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.error(str(e))
        return Response(resp)

platform_list = ['阅读思考', '阅历','搜藏']

class AuthView(APIView):
    """
    1.点击授权，弹出角色对应的所有平台名称，和提交按钮
    2.平台名称前可以勾选，点击提交，给角色授权成功返回角色页面
    """
    def post(self, request):
        try:
            # 前端点击授权，弹出角色对应的所有平台名称，和提交按钮
            # 三个平台
            role_id = request.POST.get('id')
            role = RoleTable.objects.get(id=role_id)
            platform1 = request.POST.get('platform1', '0')
            platform2 = request.POST.get('platform2', '0')
            platform3 = request.POST.get('platform3', '0')
            platform_vlue = [platform1, platform2, platform3]
            plat_zip = zip(platform_list, platform_vlue)
            for plat in plat_zip:
                platform = PlatForm(platform=role)
                platform = PlatForm()
                platform.name = plat[0]
                platform.is_bind = plat[1]
                platform.save()
            logger.info('success')

        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.error(str(e))
            return Response(resp)

#   展示用户的平台
class ShowPlat(APIView):
    """
    3.点击角色表中的内容可以查看所有的这个角色的平台名称
    """
    def get(self, request):
        try:
            # 通过前端传过来的角色来判断这是哪个用户对应的角色
            # 在去查看这个用户对应的平台是哪个
            role_id = request.GET.get('role_id')
            role = RoleTable.objects.get(id=role_id)
            data = PlatForm.objects.filter(platform=role)
            data_list = []
            for dt in data:
                name = dt.name
                is_bind = dt.is_bind
                data_list.append([name, is_bind])
            resp = {
            'platform1': {
                'name': data_list[0][0],
                'id_bind': data_list[0][1]
            },
            'platform2': {
                'name': data_list[1][0],
                'id_bind': data_list[1][1]
            },
            'platform3': {
                'name': data_list[2][0],
                'id_bind': data_list[2][1]
            },
            }
        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.error(str(e))
        return Response(resp)

# 展示所有平台

class ShowAllPlat(APIView):
    def get(self,request):
        try:
            # all_plat=PlatForm.objects.get()
            resp_list=["spiderkeeper","gitlab","wenkin"]
            # for i in all_plat:
            #     resp_list.append(i.name)
            resp={
                'code': 100,
                'message': 'success',
                'data': resp_list
            }
            logger.info('plat show all success')
        except Exception as e:
            resp = {
                'code': 101,
                'message': str(e)
            }
            logger.error(str(e))
        return Response(resp)

