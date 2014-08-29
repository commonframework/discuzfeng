#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests,re,sys,platform,time,json
from cookielib import Cookie, CookieJar
import pdb

g_checkcode_img = 'conf/checkcode.jpeg'

def check_return_content(result):
    if '\u8d26\u53f7\u4fe1\u606f\u4e0d\u80fd\u4e3a\u7a7a' in result:
        return '账号信息不能为空'
    elif '\u9a8c\u8bc1\u7801\u9519\u8bef' in result:
        return '验证码错误'
    elif '\u8bf7\u6c42\u6210\u529f' in result:
        return '请求成功'
    elif '\u5a01\u950b\u7f51\u8bba\u575b' in result:
        return '威锋网论坛'
    elif '\u64cd\u4f5c\u6210\u529f' in result:
        return '操作成功'
    elif '\u8bf7\u8f93\u5165\u9a8c\u8bc1\u7801' in result:
        return '请输入验证码'
    else:
        return 'unknown'

class FengPhpwind:
    def __init__(self, username, password):
        self.username= username
        self.password = password
        self.platform = platform.system()
        self.session = requests.Session()
    def login(self):
        c = Cookie(version=0, name='username', value=self.username, port=None, port_specified=False, domain='passport.feng.com', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={}, rfc2109=False)
        un_cookies = {'username':self.username}
        login_url = 'http://bbs.feng.com/member.php?mod=logging&action=login'
        #添加头字段,模拟从bbs.feng.com跳转到登陆页面
        linux_firefox_headers = {
             'Host':'bbs.feng.com',
             'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
             'Referer':'http://bbs.feng.com/',
             'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
             'Connection':'keep-alive',
             'Accept-Language':'en-US,en;q=0.5'
        }
        mac_firefox_headers = [
             ('Host','bbs.feng.com'),
             ('User-Agent','Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:30.0) Gecko/20100101 Firefox/30.0'),
             ('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
             ('Accept-Language','zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3'),
             ('Connection','keep-alive'),
             ('Referer','http://bbs.feng.com/')
        ]
        if self.platform=='Linux':
            headers = linux_firefox_headers
        else:
            headers = mac_firefox_headers
        url = login_url
        #http://passport.feng.com/?r=user/login&sso%5Bjump%5D=http%3A%2F%2Fbbs.feng.com%2F&sso%5Bname%5D=%E5%A8%81%E9%94%8B%E8%AE%BA%E5%9D%9B&sso%5Bapps%5D=2&sso%5Bverify%5D=7a928982dd59b02a3024858bd61ccf22
        #r = self.session.get(url,headers=headers)
        #TODO get 
        print "INFO >>> Login() === : logging home: ",url
        r = self.session.get(url)
        redirect_logging_url = r.url
        #redirect_logging_url = 'http://bbs.feng.com/member.php?mod=logging&action=login'

        #02. Login redirect 打开重定向地址
        osx_loginprocess_headers = {'Host':'passport.feng.com',
            'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:30.0) Gecko/20100101 Firefox/30.0',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3'
        }
        ubuntu_loginprocess_headers = {'Host':'passport.feng.com',
            'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':'en-US,en;q=0.5',
            'Connection':'keep-alive',
            'Referer':'http://bbs.feng.com/'
        }
        url = redirect_logging_url
        headers = (ubuntu_loginprocess_headers if self.platform == 'Linux' else osx_loginprocess_headers)
        print "INFO >>> Login() === : Get redirect: ",url
        r = self.session.get(url,headers=headers)
        result = r.content
        checkcodeImgUrltRE = u'(?<=\'/index\.php\?r=site/ValidateCode&t=)\d+(?=\'\;)'
        checkcodeImgUrlt = re.findall(checkcodeImgUrltRE,result)
        if len(checkcodeImgUrlt) > 0:
            checkcodeImgUrlt = checkcodeImgUrlt[0]
        else:
            print 'ERROR >>> Can not get check code image url, exit!'
            print result
            sys.exit(1)

        #Open ValidateCode/Check code  url
        postfix_timestamp = int(time.time()*1000)/5000
        validate_code_url = 'http://passport.feng.com/index.php?r=site/ValidateCode&t=%d&_=%d'%(int(checkcodeImgUrlt),postfix_timestamp)
        validate_headers = {'Host':'passport.feng.com',
            'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Accept':'image/png,image/*;q=0.8,*/*;q=0.5',
            'Accept-Language':'en-US,en;q=0.5',
            'Connection':'keep-alive',
            'Referer':redirect_logging_url
        }
        print "INFO >>> Login() === : Get validate code: ",validate_code_url
        url = validate_code_url
        headers = validate_headers
        r = self.session.get(url,headers=headers)
        checkcode_img = r.content

        localimg = open(g_checkcode_img,"wb")
        localimg.write(checkcode_img)
        localimg.close()
        print "INFO >>> Login() === :请到%s,打开验证码图片"%g_checkcode_img
        checkcode = '1234'
        #checkcode = raw_input("INFO >>> Login() === :请输入验证码：")

        #检查用户状态 Check user status
        millisecond = int(time.time()*1000)
        check_userstatus_url ='http://passport.feng.com/index.php?r=user/CheckUserStatus&username=%s&password=&_=%d'%(self.username,millisecond)
        check_us_headers = {
            'Host':'passport.feng.com',
            'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Accept':'application/json, text/javascript, */*; q=0.01',
            'Accept-Language':'en-US,en;q=0.5',
            'X-Requested-With':'XMLHttpRequest',
            'Connection':'keep-alive',
            'Referer':redirect_logging_url
        }
        url = check_userstatus_url
        headers = check_us_headers
        print "INFO >>> Login() === :1 CheckUserStatus: ",check_userstatus_url
        r = self.session.get(url,headers=headers)
        check_us_result = r.content
        if "\u8bf7\u6c42\u6210\u529f" in check_us_result:
            print 'DBG  >>> Login() === :1 CheckUserStatus Content:',check_us_result + check_return_content(check_us_result)

        #检查用户状态 Check user status
        #TODO 这一步的作用是什么？
        millisecond = int(time.time()*1000)
        check_userstatus_url ='http://passport.feng.com/index.php?r=user/CheckUserStatus&username=%s&password=%s&_=%d'%(self.username,self.password,millisecond)
        check_us_headers = {
            'Host':'passport.feng.com',
            'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Accept':'application/json, text/javascript, */*; q=0.01',
            'Accept-Language':'en-US,en;q=0.5',
            'X-Requested-With':'XMLHttpRequest',
            'Connection':'keep-alive',
            'Referer':redirect_logging_url
        }
        print "INFO >>> Login() === :2 CheckUserStatus: ",check_userstatus_url
        url = check_userstatus_url
        headers = check_us_headers
        #pdb.set_trace()
        #self.session.cookies.set(c)
        #r = self.session.get(url,headers=headers)
        r = self.session.get(url,headers=headers,cookies=un_cookies)
        check_us_result = r.content
        if "\u8bf7\u6c42\u6210\u529f" in check_us_result:
            print 'DBG  >>> Login() === :2 CheckUserStatus Content:',check_us_result + check_return_content(check_us_result)

        #loginProcess POST
        postdata = {
        'username=':self.username,
        'password=':self.password,
        'wekey_token=':'',
        'check_code=':checkcode
        }
        loginprocess_headers = {
            'Host':'passport.feng.com',
            'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Accept':'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With':'XMLHttpRequest',
            'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer':redirect_logging_url,
            'Accept-Encoding':'gzip, deflate',
            'Connection':'keep-alive',
            'Accept-Language':'en-US,en;q=0.5'
        }
        post_url = 'http://passport.feng.com/index.php?r=user/LoginProcess'
        url = post_url
        headers = loginprocess_headers
        print "INFO >>> Login() === :POST        : ",post_url
        print 'DBG  >>> Login() === :postdata    : ',postdata
        #r = self.session.post(url,headers=headers,data=postdata)
        r = self.session.post(url,headers=headers,data=postdata,cookies=un_cookies)
        result = r.content
        api_uc_urlRE=(r'(?<=src=")http://bbs.+(?=" )')
        api_uc_url=re.findall(api_uc_urlRE,result)
        if len(api_uc_url) < 1:
            print 'ERROR>>> Can not get http://bbs.feng.com/api/uc.php?time=xxx&code=xxx&_=xxx'
            print result + check_return_content(result)
            sys.exit(1)
        pdb.set_trace()

        r = self.session.post(url,headers=headers,data=postdata,cookies=un_cookies)
        result = r.content
        print result
        redirect_logging_url = r.url

#    @classmethod    
    def verifi_login(self):
        print '1'

if __name__ == '__main__':

    import requests
    import logging
    # these two lines enable debugging at httplib level (requests->urllib3->httplib)
    # you will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
    # the only thing missing will be the response.body which is not logged.
    import httplib
    httplib.HTTPConnection.debuglevel = 1
    logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

    reload(sys)
    sys.setdefaultencoding('utf8')

    xclass = FengPhpwind("nexusfeng","123456feng") #账号密码
    xclass.login()

    print '=================='
