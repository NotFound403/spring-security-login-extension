## Spring Security 登录插件
灵活、无侵入、可插拔，这么牛，必须Star一个！
## 使用方法
自行使用Maven`mvn install`到本地仓库，然后引入：
```xml
        <dependency>
            <groupId>cn.felord</groupId>
            <artifactId>spring-security-extension</artifactId>
            <version>1.0.0</version>
        </dependency>
```
然后参考**sample**项目进行开发。
## 相关知识
- 个人博客  [码农小胖哥的博客:https://www.felord.cn/](https://www.felord.cn/)
- 公众号：码农小胖哥  
![](./qr.jpg)
### 福利
关注公众号：码农小胖哥  回复 **2021开工福利** 和 **2022开工福利** 获取原创50万字的PDF。
### OAuth2 系列教程
[Spring Security 与 OAuth2](https://blog.csdn.net/qq_35067322/category_11691173.html)专题教程
<img src="tutorial.png" style="zoom:75%;" />
#### DEMO
- Github：https://github.com/NotFound403/felord/spring-security-oauth2-tutorial 
- Gitee： https://gitee.com/felord/spring-security-oauth2-tutorial
目前的分支有：
- [x] **main**  体验Gitee三方授权。
- [x] **wechat**  微信网页授权实现，对非标准OAuth2的定制改造，强调自定义能力。
- [x] **oauth2client** 体验Spring Security OAuth2 Client功能。
- [x] **resourceserver** 体验OAuth2 资源服务器功能。
- [x] **jose**  jose规范讲解体验，十分重要，必须熟练掌握。
- [x] **springauthserver** Spring Authorization Server初步体验入门。
- [x] **customconsent** Spring Authorization Server自定义授权确认（consent required）页面。
- [x] **privatekeyjwt** OAuth2客户端授权方式（Client Authentication Method）`private_key_jwt`实现（独家）。
- [x] **clientsecretjwt** OAuth2客户端授权方式（Client Authentication Method）`client_secret_jwt`实现（独家）。
- [ ] **其它新分支持续更新中**
#### 目录（更新中）

## 登录方式
登录方式有三种。
### 普通登录

```http request
POST /login?username=user&password=12345 HTTP/1.1
Host: localhost:8085
```
### 验证码登录
> 需要先实现必须的配置接口

发送验证码后调用验证码登录接口：
```http request
POST /login/captcha?phone=11111111111&captcha=123123 HTTP/1.1
Host: localhost:8080
```
### 小程序登录
> 需要先实现必须的配置接口

前端先调用微信授权登录接口获取`openid`:
```http request
POST /miniapp/preauth?clientId=wxxda23234&jsCode=051A23234ZHa1tZ5yj3AOlFr HTTP/1.1
Host: localhost:8080
```
响应：
```json
{
    "code": 200,
    "data": {
        "errcode": null,
        "errmsg": null,
        "sessionKey": null,
        "openid": "oWmZj5QBrZxxxxx8OUxRrZJi4",
        "unionid": "oS-dxxxxxx4w_x7dA-h9MIuA"
    },
    "msg": "",
    "identifier": true
}
```
然后调用小程序登录接口：
```http request
POST /login/miniapp HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{
    "clientId": "wxd14qr6",
    "openId": "oWmZj5QBrZIBks0xx8OUxRrZJi4",
    "unionId": "oS-dK520tgW8xxxx7dA-h9MIuA",
    "iv":"LQUOt8BSTa7xxxpe1Q==",
    "encryptedData": "10hn3o4xxxxxrO/Ag5nRD3QkLSzduKnWuzN9B/H4Y0G5mDPR8siA7T8yaaqZsrMycLAoe2qrd1J75yYetYuWifiq3jUrcceRZHVxxl9LnQdW8f5+pMTnQtCYiMJ7Jm9paCw2Bh+5Lowkyqkx1q0fALvCQ9LXPPLAbLOB9CavRfKoenAmyyHQjZ/6lz0njzA=="
}
```
## JWT

### JWT 密钥证书

利用Keytool工具生成，采用RSA算法时为：

```
 keytool -genkey -alias nashi  -keyalg RSA -storetype PKCS12 -keysize 2048 -validity 365 -keystore /path/keystores/jwt.jks -storepass Nashi6x123akg15v13  -dname "CN=(Nashi), OU=(Nashi), O=(Nashi), L=(zz), ST=(hn), C=(cn)"
```