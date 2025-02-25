import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime

# 原始代码中的解密函数
def aes_decrypt(ciphertext, key, iv):
    cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
    plaintext = b''.join([cipher.decrypt(ciphertext[i:i+16]) 
                        for i in range(0, len(ciphertext), 16)])
    # 移除PKCS7填充
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]

# 生成订阅文件的主逻辑
def generate_subscription():
    # 原始请求参数
    api_url = 'http://api.skrapp.net/api/serverlist'
    headers = {
        'accept': '/',
        'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
        'appversion': '1.3.1',
        'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
        'content-type': 'application/x-www-form-urlencoded',
        'Cookie': 'PHPSESSID=fnffo1ivhvt0ouo6ebqn86a0d4'
    }
    data = {'data': '4265a9c353cd8624fd2bc7b5d75d2f18b1b5e66ccd37e2dfa628bcb8f73db2f14ba98bc6a1d8d0d1c7ff1ef0823b11264d0addaba2bd6a30bdefe06f4ba994ed'}
    key = b'65151f8d966bf596'
    iv = b'88ca0f0ea1ecf975'

    # 发送请求
    response = requests.post(api_url, headers=headers, data=data)
    
    if response.status_code == 200:
        encrypted_data = binascii.unhexlify(response.text.strip())
        decrypted_data = aes_decrypt(encrypted_data, key, iv)
        servers = json.loads(decrypted_data)

        # 生成节点列表
        ss_links = []
        for server in servers['data']:
            # 构建SS URI
            method = "aes-256-cfb"
            password = server['password']
            ip = server['ip']
            port = server['port']
            
            ss_uri = f"{method}:{password}@{ip}:{port}"
            b64_uri = base64.urlsafe_b64encode(ss_uri.encode()).decode()
            full_link = f"ss://{b64_uri}#{server['title']}"
            
            ss_links.append(full_link)

        # 生成订阅内容（Base64编码）
        subscription_content = '\n'.join(ss_links)
        encoded_content = base64.urlsafe_b64encode(
            subscription_content.encode()).decode()

        # 写入文件
        with open('subscription.txt', 'w') as f:
            f.write(encoded_content)
        print("订阅文件已生成")
    else:
        print(f"API请求失败，状态码：{response.status_code}")

# 主程序
if __name__ == "__main__":
    print("="*50)
    print("Shadowsocks 订阅生成器")
    print(f"更新时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)
    
    generate_subscription()