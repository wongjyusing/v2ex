## 问题已解决
大家可以看一下后端的代码  
```python
# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
class User(AbstractUser):
    LEVEL_TYPE = (
        (0,'普通用户'),
        (1,'一级用户'),
        (2,'二级用户'),
        (3,'三级用户'),
        (4,'四级用户'),
        (5,'至尊用户'),
    )
    nickname = models.CharField(max_length=50, unique=True,verbose_name='昵称')
    user_level = models.IntegerField(choices=LEVEL_TYPE,verbose_name='用户级别',help_text='等级',default=0)
    user_consumption = models.FloatField(default=0, verbose_name="用户消费总金额")
    invitation_user_count = models.IntegerField(verbose_name='邀请的用户数量',default=0)
    invitation_code = models.CharField(max_length=50, unique=True,verbose_name='邀请码',default='1234567890')
    # 字段命名
    class Meta:
        db_table = "users"
        verbose_name = '用户'
        verbose_name_plural = verbose_name
    # 返回字段名
    def __str__(self):
        return self.username

class InvitationCode(models.Model):
    invitation_user = models.IntegerField(verbose_name='所属的用户id',default=0)
    invitation_code = models.CharField(max_length=12, unique=True,verbose_name='邀请码')

    class Meta:
        db_table = "invitation_code"
        verbose_name = '邀请码'
        verbose_name_plural = verbose_name
```
### 数据序列化
```python
# serializers.py
from django.contrib.auth import get_user_model
User = get_user_model()
from my_user.models import InvitationCode
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from itsdangerous import TimedJSONWebSignatureSerializer as TJWT

import random
import string
import requests
import json

class UserRegisteredSerializer(serializers.Serializer):
    # 注意，不需要返回的字段要把 write_only设为真
    recaptcha = serializers.CharField(
                                    label="验证码",
                                    help_text="验证码",
                                    required=True,
                                    allow_blank=False,
                                    write_only=True,
                                    max_length=500,
                                     )

    invitation_code = serializers.CharField(
                                    label="邀请码",
                                    help_text="邀请码",
                                    required=True,
                                    allow_blank=True,
                                    max_length=12,
                                     )
    username = serializers.CharField(
                                    label="用户名",
                                    help_text="用户名",
                                    required=True,
                                    allow_blank=False,
                                    min_length=6,
                                    max_length=22,
                                     validators=[UniqueValidator(queryset=User.objects.all(), message="用户已经存在")]
                                     )
    nickname = serializers.CharField(
                                    label="昵称",
                                    help_text="昵称",
                                    required=True,
                                    allow_blank=False,
                                    min_length=6,
                                    max_length=22,
                                    validators=[UniqueValidator(queryset=User.objects.all(), message="昵称已经存在")]
                                    )

    password1 = serializers.CharField(
        min_length=8,allow_blank=False,
        style={'input_type': 'password'},help_text="密码", label="密码", write_only=True,
    )
    password2 = serializers.CharField(
        min_length=8,allow_blank=False,
        style={'input_type': 'password'},help_text="密码确认", label="密码确认", write_only=True,
    )
    email = serializers.EmailField(required=True,help_text="Email",label="邮箱",validators=[UniqueValidator(queryset=User.objects.all(), message="该邮箱已经被注册")])


    def validate(self, data):
        # 注意，secret的参数是从recaptcha中获取。

        '''
        验证recaptcha验证码是否正确
        '''
        response_data = {
            'secret': 'xxxxx',
            'remoteip': '127.0.0.1',
        }
        response_data['response'] = self.initial_data["recaptcha"]
        response = requests.post('https://www.google.com/recaptcha/api/siteverify',response_data)
        verify_response = json.loads(response.text)
        if verify_response['success'] == False:
            raise serializers.ValidationError(verify_response['error-codes'])

        '''
        判断两次的密码是否正确。
        '''
        if self.initial_data["password1"] != self.initial_data["password2"]:
            raise serializers.ValidationError("两次输入的密码不相同")

        # 验证两次密码成功后，删除
        del data['password1']
        del data['password2']

        # 验证邀请码
        if data['invitation_code'].isalnum():

            verify_records = InvitationCode.objects.filter(invitation_code=self.initial_data["invitation_code"])
            if verify_records.count() != 0:
                verify_record = verify_records[0]
                user = User.objects.get(pk=verify_record.invitation_user)
                user.invitation_user_count +=1
                user.save()
            else:
                raise serializers.ValidationError("邀请码错误")

        data['password'] = self.initial_data["password1"]
        # 生成用户的邀请码
        data['invitation_code'] = self.generate_invitation_code()

        '''
        把用户激活状态设为False
        需要用户到邮箱中激活
        '''
        data['is_active'] = False

        return data



    def create(self, validated_data):
        """
        创建用户
        """
        # 删除验证通过数据的 recaptcha参数
        del validated_data['recaptcha']
        user = User.objects.create(**validated_data)
        user.set_password(validated_data['password'])
        user.save()

        user_id = user.id
        user_invitation_code = user.invitation_code
        existed = InvitationCode.objects.create(invitation_user=user_id,invitation_code=user_invitation_code)

        return validated_data

    def generate_invitation_code(self):
        salt = ''.join(random.sample(string.ascii_letters + string.digits, 10))
        verify_records = InvitationCode.objects.filter(invitation_code=salt)
        if verify_records.count() > 0:
            salt = ''.join(random.sample(string.ascii_letters + string.digits, 11))
        return salt.upper()

```

### 视图处理

```python
# views.py
from django.contrib.auth import get_user_model
User = get_user_model()
from django.contrib.auth.backends import ModelBackend
from rest_framework import mixins,viewsets
from rest_framework import permissions
from rest_framework import authentication
from rest_framework.response import Response
from rest_framework import status
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

from rest_framework_jwt.serializers import jwt_encode_handler, jwt_payload_handler

from .serializers import UserRegisteredSerializer

class UserViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):

    serializer_class = UserRegisteredSerializer
    queryset = User.objects.all()
    authentication_classes = (JSONWebTokenAuthentication,)
```

# 前端Angular-cli
```typescript
// app.module.ts
...
import { AppComponent } from './app.component';
import { RecaptchaModule } from 'ng-recaptcha';
import { RecaptchaFormsModule } from 'ng-recaptcha/forms';
...
@NgModule({
    imports: [
        ...
        RecaptchaModule,
        RecaptchaFormsModule,
        ...
    ]
})
```


### loginComponents.ts
```typescript
import { Component, OnInit } from '@angular/core';
import { AuthService } from 'src/app/auth.service';
import { Router } from '@angular/router';


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class AuthModalComponent implements OnInit {

  public register_data: {
    username: string,
    password1: string,
    password2: string,
    nickname: string,
    email: string,
    invitation_code: string,
    recaptcha: string,
  }

  constructor(
    private auth: AuthService,
    private router: Router,
  ) { }

  ngOnInit() {

    this.register_data = {
      username: '',
      password1: '',
      password2: '',
      nickname: '',
      email: '',
      invitation_code: '',
      recaptcha:''
    }
  }


  // 注册函数
  public RegisterSubmit = () => {
    this.auth.register(this.register_data).subscribe(
      data => {
        this.nickname = localStorage.getItem('nickname')

      },
      error => {
        console.log(error);


      }

    )
  };

  resolved(captchaResponse: string) {
    console.log(captchaResponse);
    this.register_data.recaptcha = captchaResponse;
    console.log(this.register_data);
  }
}

```

### html
```html
<div>
    <label for="validationServer01">Username</label>
    <input type="text" [(ngModel)]='register_data.username' class="form-control" id="validationServer03" placeholder="Username" required>
    <label for="validationServer02">Password</label>
    <input type="password" [(ngModel)]='register_data.password1' class="form-control" id="validationServer04" placeholder="password" required>
    <label for="validationServer02">Password Validation</label>
    <input type="password" [(ngModel)]='register_data.password2' class="form-control" id="validationServer05" placeholder="Password Validation" required>
    <label for="validationServer01">nickname</label>
    <input type="text" [(ngModel)]='register_data.nickname' class="form-control" id="validationServer06" placeholder="nickname" required>
    <label for="validationServer01">Invitation Code</label>
    <input type="text" [(ngModel)]='register_data.invitation_code' class="form-control" id="validationServer07" placeholder="invitation Code" required>
    <label for="validationServer01">Email</label>
    <input type="email" [(ngModel)]='register_data.email' class="form-control" id="validationServer08" placeholder="Email" required>
    <re-captcha #captchaRef="reCaptcha" siteKey="6LffQKwUAAAAALnABhl0ssomm5uRjMWlXotvFN_T" (resolved)="resolved($event)"></re-captcha>
</div>

<button type="button" (click)="RegisterSubmit()" class="btn btn-primary ">Register</button>

```

### auth.service.ts
```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { CrudHandlerService } from 'src/app/crud-handler.service';
@Injectable()
export class AuthService {

  base_url = 'http://127.0.0.1:8000';
  nickname: string;


  constructor(private http: HttpClient) { }

  login(items): Observable<boolean> {
    return this.http.post<{ token: string, nickname: string }>(this.base_url + '/jwt/login/', { username: items.username, password: items.password })
      .pipe(
        map(result => {
          localStorage.setItem('access_token', result.token);
          localStorage.setItem('nickname', result.nickname);
          this.nickname = result.nickname
          return true;
        })
      );
  }

    // 其实这里有更方便的写法，我需要验证一下安全的问题，再改进
  register(items): Observable<boolean> {
    return this.http.post<{ token: string, nickname: string }>(this.base_url + '/api/register/',
      {
        username: items.username,
        password1: items.password1,
        password2: items.password2,
        nickname: items.nickname,
        email: items.email,
        invitation_code: items.invitation_code,
        recaptcha: items.recaptcha

      }
    )
      .pipe(
        map(result => {
          console.log(result);
          localStorage.setItem('access_token', result.token);
          localStorage.setItem('nickname', result.nickname);
          this.nickname = result.nickname
          return true;
        })
      );
  }

  logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('nickname');
    localStorage.removeItem('shoppingcart');


  }


  public get loggedIn(): boolean {
    return (localStorage.getItem('access_token') !== null);
  }
}

```
