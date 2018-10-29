import base64
import os
import sys
import subprocess
import json
import traceback
import xml.etree.ElementTree as ET
import codecs
import urllib.request as urllib2
import chardet

import config
import log
import is_connect
import process

# 任务id
task_id = ''
# 子任务id
# subtask_id = ''
# 获取进度id
pro_uuid = ''
# 任务名称
task_name = ''
# 白名单(0) or 云平台(1)
platform = ''
# 是否需要探测os、服务版本
extra_info = ''
# 结果列表
server_list = {}
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)



# 端口类
class Port:
    def __init__(self, port, service_sof, version, url, protocol, headers):
        self.port = port
        self.service_sof = service_sof
        self.version = version
        self.url = url
        self.protocol = protocol
        self.headers = headers

    def to_dict(self):
        return {
            "port": self.port,
            "service_sof": self.service_sof,
            "version": self.version,
            # "banner": str(base64.b64encode(self.banner.encode('utf-8')))[2:-1]
            "url": self.url,
            "protocol": self.protocol,
            "headers": self.headers
        }


# 任务类
class WebServer:
    def __init__(self, ip):
        self.ip = ip
        self.ports = []
        self.hardware = ''
        self.os_version = ''

    def to_dict(self):
        temp_ports = []
        for port in self.ports:
            temp_ports.append(port.to_dict())
        return {
            "ip": self.ip,
            "ports": temp_ports,
            "hardware": self.hardware,
            "os_version": self.os_version
        }


# 获取配置
def get_config():
    global task_id
    global task_name
    global pro_uuid
    global platform
    # global subtask_id
    global extra_info

    with open(config.CONFIG_FILE, 'r') as f:
        task = base64.b64decode(f.read()).decode('utf-8').split(';')
    print(task)
    task_id = task[0]
    # subtask_id = task[1]
    pro_uuid = task[5]
    task_name = task[1]
    platform = task[2]
    extra_info = task[3]
    ip_list = task[4].split(',')
    with open(config.TARGET_LIST, 'w') as dns_f:
        dns_f.write('\n'.join(ip_list))
    if os.path.getsize(config.TARGET_LIST) <= 0:
        e = 'No target IP.'
        log.get_conf_fail()
        log.write_error_to_appstatus(e, 3)


# zmap + zgrab
def zmap_zgrab(port):
    json_file = config.ZGRAB_JSON + '-' + str(port)
    # mac_origin = uuid.UUID(int=uuid.getnode()).hex[-12:]
    # mac = ":".join([mac_origin[e:e+2] for e in range(0,11,2)])
    if port == 443:
        tls = '--tls'
    else:
        tls = ''
    if platform == '1':
        process = os.popen("route | grep '0.0.0.0' | grep '128.0.0.0' | awk '{print $8}' ")  # return file
        output = process.read()
        process.close()
        outif_zmap = ' -i ' + output[:-1]
        outif_zgrab = ' -interface ' + output[:-1]
    else:
        outif_zgrab = outif_zmap = ''
    command = (
        'zmap -p {port}{outif_zmap} --whitelist-file={target} --output-module=csv --output-fields=* -r 1000 | '
        'ztee results.csv | '
        'zgrab --port {port} {tls} --http="/"{outif_zgrab} --output-file={output}'
    ).format(
        port=str(port),
        outif_zmap=outif_zmap,
        target=config.TARGET_LIST,
        output=json_file,
        tls=tls,
        outif_zgrab=outif_zgrab
    )
    print('command: ' + command)
    subprocess.call([command], shell=True)
    print(command)


#  json提取, 过滤未开启http服务的ip
def get_base_info(port):
    global server_list
    # 格式化json
    json_file = config.ZGRAB_JSON + '-' + str(port)
    command = (
        "sed 's/{{\"ip\":/,{{\"ip\":/g' {file} | sed '1s/.//' | sed '1s/^/[&/' | sed '$a]' > tmp_file ;"
        "rm -rf {file} ;mv tmp_file {file} ;"
    ).format(file=json_file)
    print(command)
    subprocess.call([command], shell=True)
    if os.path.getsize(json_file) > 0:
        try:
            with open(json_file, 'rb') as f:
                encoding_result = chardet.detect(f.read())
            with codecs.open(json_file, 'r', encoding=encoding_result['encoding']) as f:
                base_info = json.load(f)
        except:
            return
    else:
        base_info = {}
    for line in base_info:
        if 'error' in line:
            continue
        # 端口对应信息
        try:
            service_temp = line['data']['http']['response']['headers']['server'][0]
            if service_temp.find(' ') >= 0:
                service = service_temp[:service_temp.find(' ')]
            else:
                service = service_temp
            if service.find('/') >= 0:
                service_sof = service[:service.find('/')]
                version = service[service.find('/'):]
            else:
                service_sof = service
                version = ''
        except KeyError:
            service_sof = ''
            version = ''

        # server_port = Port(port, service_sof, version, json.dumps(line))
        server_port = Port(port,
                           service_sof,
                           version,
                           str(line['data']['http']['response']['request']['url']),
                           str(line['data']['http']['response']['protocol']),
                           str(line['data']['http']['response']['headers']))
        ip = line['ip']
        # 更新ip列表
        try:
            server_list[ip].ports.append(server_port)
        except KeyError:
            server_list[ip] = WebServer(ip)
            server_list[ip].ports.append(server_port)


def writeandnmap(ip_list):
    with open(config.NMAP_LIST, 'w') as f:
        f.write(ip_list)
    command = 'nmap -O -Pn -sS -p 8000,443,80,8080 -iL {input_file} -oX {output}'.format(input_file=config.NMAP_LIST,
                                                                                         output=config.NMAP_XML)
    subprocess.call([command], shell=True)
    if os.path.getsize(config.NMAP_XML) > 0:
        with open(config.NMAP_XML, 'r') as f:
            xml = ET.ElementTree(file=f)
        for host in xml.findall('.//host'):
            ip = host.find('./address').attrib['addr']
            os_ele = host.find('.//osmatch')
            os_version = 'unknown'
            if os_ele is not None:
                try:
                    os_version = os_ele.attrib['name']
                except KeyError:
                    pass
            os_class_ele = host.find('.//osclass')
            device_type = 'unknown'
            if os_class_ele is not None:
                try:
                    device_type = os_class_ele.attrib['type']
                except KeyError:
                    pass
            server_list[ip].hardware = device_type
            server_list[ip].os_version = os_version
    else:
        pass


# nmap探测设备种类和操作系统
def nmap():
    # 生成ip列表
    ip_list = ''
    i = 0
    for ip in server_list:
        ip_list += (ip + '\n')
        i = i + 1
        if i == 50:
            writeandnmap(ip_list)
            ip_list = ''
            i = 0
    if i != 0:
        writeandnmap(ip_list)


# 根据平台生成结果
def write_result_on_whitelist_server():
    result_file_name = '{task_id}-{tag}.result'
    for host in server_list:
        content = {
            'task_id': task_id,
            'task_name': task_name,
            'result': server_list[host].to_dict()
        }
        with codecs.open(os.path.join(
                config.RESULT_FILE,
                result_file_name.format(task_id=task_id, tag=host)
        ), 'w', 'utf-8') as f:
            json.dump(content, f, ensure_ascii=False)


def write_result_on_cloud_server():
    result = []
    for host in server_list:
        result.append(server_list[host].to_dict())
    with codecs.open(os.path.join(config.RESULT_FILE, task_id + '.result'), 'w', 'utf-8') as f:
        json.dump({
            'task_id': task_id,
            'task_name': task_name,
            'result': result
        }, f, ensure_ascii=False)


if __name__ == '__main__':
    log.task_start()
    try:
        os.makedirs(config.LOG_FILE)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.APP_STATUS)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.RESULT_FILE)
    except FileExistsError:
        pass
    # if not is_connect.NetCheck():
    #     log.task_fail()
    #     log.write_result_fail()
    #     e = 'Can not connect to the Internet.'
    #     print(e)
    #     write_error_to_appstatus(e)
    #     sys.exit(-1)
    # 判断网络
    is_connect.Update()
    # try:
    #    ex_ip = urllib2.urlopen("http://ip.6655.com/ip.aspx").read().decode()
    # except:
    #    ex_ip = ''
    # if ex_ip is '':
    #    log.task_fail()
    #    log.write_result_fail()
    #    e = 'Can not get external IP address.'
    #   print(e)
    #   log.write_error_to_appstatus(e, 2)
    # 获取配置
    log.get_conf()
    try:
        get_config()
        log.get_conf_success()
    except Exception as e:
        log.get_conf_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 计次初始化
    processer = process.processManager()
    prtaskid = task_id.split("-")
    try:
        prtaskid = prtaskid[-1]
    except:
        prtaskid = task_id
    processer.set_taskid(prtaskid, pro_uuid)
    # 执行任务
    log.task_run()
    try:
        # subprocess.call(['wget http://www.baidu.com'], shell=True)
        for port in config.PORT_SET:
            zmap_zgrab(port)
            get_base_info(port)
            # 计次
            processer.resultCreate()
        # 计次结束
        processer.final_send()
        if extra_info == '1':
            nmap()
    except Exception as e:
        traceback.print_exc()
        result = ''
        log.task_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 写结果
    log.write_result()
    try:
        if platform == '0':
            write_result_on_whitelist_server()
        else:
            write_result_on_cloud_server()
        log.write_result_success()
    except Exception as e:
        traceback.print_exc()
        log.write_result_fail()
        log.write_error_to_appstatus(str(e), -1)
    log.write_success_to_appstatus()
