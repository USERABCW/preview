import datetime  
import os.path  
import socket  
import ssl  
import threading  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad, unpad    
from Crypto.Random import get_random_bytes    
"""  
使用AES对聊天记录进行加密  
"""  
class ChatRecorder:  
    def __init__(self):  
        """  
        :param passwd: 加密密码,长度不能超过16字节,默认为000000  
        """  
        self.passwd = passwd.encode('utf-8').ljust(16, b'\x00')[:16]  
        self.buff = ""  
  
    def chat_record(self, sender, content):  
        """  
        记录聊天信息  
        :param sender: 发送者  
        :param content: 聊天内容  
        """  
        # 生成聊天记录的字符串  
        msg = "[{}] [{}] {}".format(sender, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), content)  
        # 保存到缓存中  
        #print(msg)
        self.buff += "\n{}".format(msg)  
  
    def chat_cipher(self, file_path):  
        """  
        保存聊天记录到文件  
        :param file_path: 文件路径  
        """   
        key = self.passwd  
        block_size = AES.block_size  
        # 创建一个AES对象，使用ECB模式  
        cipher = AES.new(key, AES.MODE_ECB)  
        # 将缓存转换为bytes类型  
        plaintext = self.buff.encode('utf-8') 
        #print(plaintext) 
        # 使文本的长度是block_size的整数倍  
        padded_plaintext = pad(plaintext, block_size)  
        # 加密文本  
        ciphertext = cipher.encrypt(padded_plaintext)  
        # 将加密后的文本保存到文件中  
        with open(file_path, "wb") as file:  
            file.write(ciphertext)  
  
class SSLClient:    
    """    
    SSL/TLS 客户端处理类    
    """    
    def __init__(self, client_socket, addr):    
        self.client_socket = client_socket    
        self.addr = addr    
        self.recorder = ChatRecorder()  
        self.flag = False
    
    def receive_messages(self):
        """    
        接收消息的线程    
        """    
        while True:    
            try:  
                data = self.client_socket.recv(1024)  
                if data:   
                    if "exit" in data.decode('utf-8').lower(): # 退出聊天室
                        print("再见!")
                        self.flag=True
                        return 
                    # 打印接收到的消息  
                    print("\r" + " " * 40 + "\r", end="")  # 清除当前行
                    print("\033[1;32m\r" + data.decode('utf-8') + "\033[0m") 
                    print("\033[1;31m\r"+username + "> \033[0m", end="")     
                    # 保存聊天记录  
                    sender = "{}:{}".format(*self.addr)  
                    self.recorder.chat_record(sender, data.decode('utf-8'))  
                else:  
                    print(f"连接来自 {self.addr} 已关闭")    
                    break  
            except Exception as e:  
                print(f"接收消息时出错: {e}")  
                self.client_socket.close()  
                break

    def send_messages(self):
        """    
        发送消息的线程    
        """     
        while True:    
            try:  
                # 读取发送的信息  
                send_data = input("\033[1;31m\r"+f"{username}> \033[0m") 
                if send_data:  
                    # 发送消息  
                    send_data = (username + "> " + send_data).encode('utf-8')  
                    self.client_socket.send(send_data) 
                    if "exit" in send_data.decode('utf-8').lower(): # 退出聊天室
                        print("再见!")
                        self.flag=True
                        return
                    sender = "{}:{}".format(*self.addr) 
                    self.recorder.chat_record(sender, send_data.decode('utf-8')) 
            except Exception as e:  
                print(f"发送消息时出错: {e}")  
                self.client_socket.close()  
                break

    def build(self):    
        """    
        处理客户端连接    
        """    
        # 启动接收和发送消息的线程
        receive_thread = threading.Thread(target=self.receive_messages)
        send_thread = threading.Thread(target=self.send_messages)
        receive_thread.daemon = True
        send_thread.daemon=True
        receive_thread.start()
        send_thread.start()
        #receive_thread.join()
        #send_thread.join()
        while True:
            if self.flag == True:
                break
        # 保存聊天记录到文件中  
        print("聊天记录已保存到文件。")
        file_path = "record/server_record_{}.txt".format(port)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)  
        self.recorder.chat_cipher(file_path)  
        self.client_socket.close()          
  
class ServerSSL:    
    """    
    SSL/TLS 服务器类    
    """    
    def __init__(self, port=2903):    
        """    
        初始化服务器    
    
        :param port: 服务器监听的端口    
        :param client_num: 最大客户端连接数    
        """    
        self.port = port      
    
    def build_server(self):    
        """    
        构建并启动SSL/TLS服务器    
        """    
        # 创建SSL上下文    
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)    
        context.verify_mode = ssl.CERT_REQUIRED  # 客户端证书验证模式    
        context.load_cert_chain('cert/server.crt', 'cert/server.key')  # 加载服务器证书和私钥    
        context.load_verify_locations('cert/ca.crt')  # 加载CA证书    
    
        # 创建服务器socket    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:    
            # 绑定监听端口 监听所有可用的网络接口  
            sock.bind(('0.0.0.0', self.port))    
            sock.listen()    
            print("服务器正在监听客户端...")    
    
            # 封装为SSL/TLS socket    
            with context.wrap_socket(sock, server_side=True) as ssock:       
                try:    
                     # 接受客户端连接    
                    client_socket, addr = ssock.accept()    
                    print(f"接受连接来自 {addr}")    
    
                    # 创建一个客户端处理对象    
                    client = SSLClient(client_socket, addr)    
                    client.build()
                    # 关闭客户端连接
                    #client_socket.close()
                except Exception as e:    
                    print(f"接受连接时出错: {e}")        

class ClientSSL:  
    def __init__(self, username, port):  
        self.username = username  # 将username作为类的属性，以便在connect_server方法中使用  
        self.port = port
        self.recorder = ChatRecorder()  # 初始化ChatRecorder实例
        self.flag=False
  
    def receive_messages(self, ssock):
        """    
        接收消息的线程    
        """    
        while True:    
            try:  
                data = ssock.recv(1024)  
                if data:
                    if "exit" in data.decode('utf-8').lower(): # 退出聊天室
                        print("再见!")
                        self.flag=True
                        return    
                    # 打印接收到的消息  
                    print("\r" + " " * 40 + "\r", end="")  # 清除当前行
                    print("\033[1;32m\r" + data.decode('utf-8') + "\033[0m") 
                    print("\033[1;31m\r"+self.username + "> \033[0m", end="")    
                    # 保存聊天记录  
                    sender = "server:"
                    self.recorder.chat_record(sender, data.decode('utf-8'))  
                else:  
                    print("连接来自服务器已关闭")    
                    break  
            except Exception as e:  
                print(f"接收消息时出错: {e}")  
                ssock.close()  
                break

    def send_messages(self, ssock):
        """    
        发送消息的线程    
        """    
        while True:    
            try:  
                # 读取发送的信息  
                send_data = input("\033[1;31m\r"+f"{self.username}> \033[0m")  
                if send_data:  
                    # 发送消息  
                    send_data = (self.username + "> " + send_data).encode('utf-8')  
                    ssock.send(send_data)
                    if "exit" in send_data.decode('utf-8').lower(): # 退出聊天室
                        print("再见!")
                        self.flag=True
                        return 
                    sender = "client:"
                    self.recorder.chat_record(sender, send_data.decode('utf-8')) 
            except Exception as e:  
                print(f"发送消息时出错: {e}")  
                ssock.close()  
                break

    def connect_server(self):  
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  
  
        context.load_verify_locations('cert/ca.crt')  
        context.load_cert_chain('cert/client.crt', 'cert/client.key')  
   
        context.check_hostname = False
  
        try:  
            with socket.create_connection(('127.0.0.1', self.port)) as sock:  
                with context.wrap_socket(sock) as ssock:  # 假设服务器主机名验证不是必需的  
                    # 启动接收和发送消息的线程
                    receive_thread = threading.Thread(target=self.receive_messages, args=(ssock,))
                    send_thread = threading.Thread(target=self.send_messages, args=(ssock,))
                    receive_thread.daemon = True
                    send_thread.daemon = True
                    receive_thread.start()
                    send_thread.start()
                    #receive_thread.join()
                    #send_thread.join()
                    while True:
                        if self.flag == True:
                            break
                    # 保存聊天记录到文件中  
                    print("聊天记录已保存到文件。")
                    file_path = "record/client_record_{}.txt".format(port)  
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)  
                    self.recorder.chat_cipher(file_path)  
                    ssock.close()  

        except (ssl.SSLError, ConnectionRefusedError, socket.timeout) as e:  
            print(f"发生错误: {e}")  
        except KeyboardInterrupt:  
            print("用户关闭连接。")  

# 示例：启动服务器或客户端    
if __name__ == "__main__":  
    global username
    global passwd
    global port
    mode = input("请选择模式 (server for 1/client for 2): ")
    if mode == "1":
        username = input("请输入用户名:") or "server"    
        passwd = input("请输入加密密码:") or "000000"  
        port = int(input("请输入服务器端口:")) or 2903
        server = ServerSSL(port)
        server.build_server()
    elif mode == "2":
        username = input("用户名: ")  or "client"
        passwd = input("请输入加密密码:") or "000000"  # 获取客户端的加密密码
        port = int(input("端口: ")) or 2903
        client = ClientSSL(username, port)  
        client.connect_server()
    else:
        print("无效的模式选择，请选择 'server' 或 'client'")

