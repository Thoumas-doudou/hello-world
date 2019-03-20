#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h> 
#include <windows.h> 
#include <time.h> 
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
using namespace std;
#pragma  comment(lib, "Ws2_32.lib") 

#define DEF_DNS_ADDRESS "10.3.9.4"	//外部DNS服务器地址（ipconfig查找，每一次都要修改10.122.203.114） 
#define LOCAL_ADDRESS "127.0.0.1"		//本地DNS服务器地址（题目设定） 
#define DNS_PORT 53						//进行DNS服务的53端口
#define BUF_SIZE 512
#define LENGTH 65
#define AMOUNT 300
#define NOTFOUND -1

//DNS报文首部
typedef struct DNSHeader
{
    unsigned short ID;
    unsigned short Flags;
    unsigned short QuestNum;
    unsigned short AnswerNum;
    unsigned short AuthorNum;
    unsigned short AdditionNum;
} DNSHDR, *pDNSHDR;

//DNS域名解析表结构
typedef struct translate
{
	string IP;						//IP地址
	string domain;					//域名
} Translate;

//ID转换表结构
typedef struct IDChange
{
	unsigned short oldID;			//原有ID
	BOOL done;						//标记是否完成解析
	SOCKADDR_IN client;				//请求者套接字地址
} IDTransform;

Translate DNS_table[AMOUNT];		//DNS域名解析表
IDTransform IDTransTable[AMOUNT];	//ID转换表
int IDcount = 0;					//转换表中的条目个数
char url[LENGTH];					//域名
SYSTEMTIME sys;                     //系统时间
int Day, Hour, Minute, Second, Milliseconds;//保存系统时间的变量

//函数：获取域名解析表
int GetTable(char *tablePath)
{
	int i=0, j, pos=0;
	string table[AMOUNT];

	ifstream infile(tablePath, ios::in);	//以读入方式打开文本文件

	if(! infile) {
		cerr << "Open" << tablePath << "error!" <<endl;
		exit(1);
	}

	//每次从文件中读入一行，直至读到文件结束符为止
	while (getline(infile, table[i]) && i < AMOUNT)
		i++;

	if (i == AMOUNT-1)
		cout << "The DNS table memory is full. " << endl;

	for (j = 0; j < i-1; j++) {
		pos = table[j].find(' ');
		if (pos > table[j].size())
			cout << "The record is not in a correct format. " << endl;
		else {
			DNS_table[j].IP = table[j].substr(0, pos);
			DNS_table[j].domain = table[j].substr(pos+1);
		}
	}

	infile.close();		//关闭文件
	cout << "Load records succeed. " << endl;

	return i-1;			//返回域名解析表中条目个数
}

//函数：获取DNS请求中的域名
void GetUrl(char *recvbuf, int recvnum)
{
	char urlname[LENGTH];
	int i = 0, j, k = 0;

	memset(url, 0, LENGTH);
	memcpy(urlname, &(recvbuf[sizeof(DNSHDR)]), recvnum-16);	//获取请求报文中的域名表示

	int len = strlen(urlname);
	
	//域名转换
	while (i < len) {
		if (urlname[i] > 0 && urlname[i] <= 63)
			for (j = urlname[i], i++; j > 0; j--, i++, k++)
				url[k] = urlname[i];
		
		if (urlname[i] != 0) {
			url[k] = '.';
		    k++;
		}
	}

	url[k] = '\0';
}

//函数：判断是否在表中找到DNS请求中的域名，找到返回下标
int IsFind(char* url, int num)
{
	int find = NOTFOUND;
	char* domain;

	for (int i = 0; i < num; i++) {
		domain = (char *)DNS_table[i].domain.c_str();
		if (strcmp(domain, url) == 0) {	//找到
			find = i;
			break;
		}
	}

	return find;
}

//函数：将请求ID转换为新的ID，并将信息写入ID转换表中
unsigned short RegisterNewID (unsigned short oID, SOCKADDR_IN temp, BOOL ifdone)
{
	srand(time(NULL));
	IDTransTable[IDcount].oldID = oID;
	IDTransTable[IDcount].client = temp;
	IDTransTable[IDcount].done  = ifdone;
	IDcount++;

	return (unsigned short)(IDcount-1);	//以表中下标作为新的ID
}

//函数：打印 时间 newID 功能 域名 IP
void DisplayInfo(unsigned short newID, int find)
{
	//打印时间
	GetLocalTime( &sys );
	if(sys.wMilliseconds >= Milliseconds)
	{
	    cout << setiosflags(ios::right) << setw(7) << setfill(' ') << (((sys.wDay - Day) * 24 + sys.wHour - Hour) * 60 + sys.wMinute - Minute) * 60 + sys.wSecond - Second;//设置宽度为7，right对齐方式
	    cout << '.' << setiosflags(ios::right) << setw(3) << setfill('0') << sys.wMilliseconds - Milliseconds;
	}
	else {
		cout << setiosflags(ios::right) << setw(7) << setfill(' ') << (((sys.wDay - Day) * 24 + sys.wHour - Hour) * 60 + sys.wMinute - Minute) * 60 + sys.wSecond - Second - 1;//设置宽度为7，right对齐方式
	    cout << '.' << setiosflags(ios::right) << setw(3) << setfill('0') << 1000 + sys.wMilliseconds - Milliseconds;
	}
	cout << "    ";

	//打印转换后新的ID
	cout.setf(ios::left);
	cout << setiosflags(ios::left) << setw(4) << setfill(' ') << newID;
	cout << "    ";

	//在表中没有找到DNS请求中的域名
	if (find == NOTFOUND) 
	{   
		//中继功能
		cout.setf(ios::left);
		cout << setiosflags(ios::left) << setw(6) << setfill(' ') << "中继";
		cout << "    ";
		//打印域名
		cout.setf(ios::left);
		cout << setiosflags(ios::left) << setw(20) << setfill(' ') << url;
		cout << "    ";
		//打印IP
		cout.setf(ios::left);
		cout << setiosflags(ios::left) << setw(20) << setfill(' ') << endl;
	}

	//在表中找到DNS请求中的域名
	else {
	    if(DNS_table[find].IP == "0.0.0.0")  //不良网站拦截
		{
			//屏蔽功能
			cout.setf(ios::left); 
		    cout << setiosflags(ios::left) << setw(6) << setfill(' ') << "屏蔽";
		    cout << "    ";
			//打印域名(加*)
			cout.setf(ios::left); 
		    cout << "*" << setiosflags(ios::left) << setw(19) << setfill(' ') << url;
		    cout << "    ";
			//打印IP
			cout.setf(ios::left); 
		    cout << setiosflags(ios::left) << setw(20) << setfill(' ') << endl;
		}

		//检索结果为普通IP地址，则向客户返回这个地址
		else {
			//服务器功能
			cout.setf(ios::left);
		    cout << setiosflags(ios::left) << setw(6) << setfill(' ') << "服务器";
		    cout << "    ";
			//打印域名
			cout.setf(ios::left);
		    cout << "*" << setiosflags(ios::left) << setw(19) << setfill(' ') << url;
		    cout << "    ";
			//打印IP
			cout.setf(ios::left);
		    cout << setiosflags(ios::left) << setw(20) << setfill(' ') << DNS_table[find].IP << endl;
		}
	}
}


int main(int argc, char** argv) 
{ 
    //变量命名 
	WSADATA wsaData; 
    SOCKET  socketServer, socketLocal;				//本地DNS和外部DNS两个套接字
    SOCKADDR_IN serverName, clientName, localName;	//本地DNS、外部DNS和请求端三个网络套接字地址
    char sendbuf[BUF_SIZE];
    char recvbuf[BUF_SIZE]; 
    char tablePath[100];//txt文件地址 
    char outerDns[16]; //？？？？？？ 
    int iLen_cli, iSend, iRecv;//第一个是客户端套接字地址长度，第二个是本地dNS从socket收到数据的字符数 
    int num;                   //第三个是 

    //赋值outerDns为外部服务器地址，tablePath为txt路径 
	{
	if (argc == 1) {
		strcpy(outerDns, DEF_DNS_ADDRESS);
		strcpy(tablePath, "C:\\Users\\lenovo\\Desktop\\dnsrelay.txt");  
		}                                                                 

	else if (argc == 2) {
		strcpy(outerDns, argv[1]);
		strcpy(tablePath, "C:\\Users\\lenovo\\Desktop\\dnsrelay.txt");
	}

	else if (argc == 3) {
		strcpy(outerDns, argv[1]);
		strcpy(tablePath, argv[2]);
	}
	} 

	num = GetTable(tablePath);						//获取域名解析表txt
	GetLocalTime(&sys);                             //保存系统的时间
   {
    Day          = sys.wDay;
    Hour         = sys.wHour;
	Minute       = sys.wMinute;
	Second       = sys.wSecond;
	Milliseconds = sys.wMilliseconds;} 

	for (int i=0; i < AMOUNT; i++) {				//初始化ID转换表IDTransTable[i]
		IDTransTable[i].oldID = 0;
		IDTransTable[i].done  = FALSE;
		memset(&(IDTransTable[i].client), 0, sizeof(SOCKADDR_IN));
	}

    WSAStartup(MAKEWORD(2,2), &wsaData);			//初始化ws2_32.dll动态链接库

	//创建并设置本地DNS和外部DNS套接字，socket()函数 
	{ 
    socketServer = socket(AF_INET, SOCK_DGRAM, 0);
	socketLocal = socket(AF_INET, SOCK_DGRAM, 0);

	localName.sin_family = AF_INET;
	localName.sin_port = htons(DNS_PORT);
	localName.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);

	serverName.sin_family = AF_INET;
	serverName.sin_port = htons(DNS_PORT);
	serverName.sin_addr.s_addr = inet_addr(outerDns);} 

	//绑定本地DNS服务器地址，bind()函数 
	{ 
	if (bind(socketLocal, (SOCKADDR*)&localName, sizeof(localName))) 
		{cout << "Binding Port 53 failed." << endl;
		exit(1);}
	else
		cout << "Binding Port 53 succeed." << endl;} 

	//本地DNS中继服务器的具体操作
	while (1) {
		iLen_cli = sizeof(clientName);
        memset(recvbuf, 0, BUF_SIZE);

		//接收DNS请求(recvfrom从已连接socket接收数据并捕获数据发送源地址） 
		iRecv = recvfrom(socketLocal, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);
        //处理接收的数据 
		if (iRecv == SOCKET_ERROR) {
			cout << "Recvfrom Failed: " << WSAGetLastError() << endl;
			continue;
		}
		else if (iRecv == 0) {
			break;
		}
		else {	
			GetUrl(recvbuf, iRecv);				//获取域名
			int find = IsFind(url, num);		//在域名解析表中查找
			cout << url <<endl;
			//在域名解析表中没有找到
			if (find == NOTFOUND) {
				//ID转换
				unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
				memcpy(pID, recvbuf, sizeof(unsigned short));
				unsigned short nID = htons(RegisterNewID(ntohs(*pID), clientName, FALSE));
				memcpy(recvbuf, &nID, sizeof(unsigned short));

				//打印 时间 newID 功能 域名 IP
				DisplayInfo(ntohs(nID), find);

				//把recvbuf转发至指定的外部DNS服务器
				iSend = sendto(socketServer, recvbuf, iRecv, 0, (SOCKADDR*)&serverName, sizeof(serverName));
				if (iSend == SOCKET_ERROR) {
					cout << "sendto Failed: " << WSAGetLastError() << endl;
					continue;
				}
				else if (iSend == 0)
					break;

				free(pID);	//释放动态分配的内存

				//接收来自外部DNS服务器的响应报文
				iRecv = recvfrom(socketServer, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);

				//ID转换
				pID = (unsigned short *)malloc(sizeof(unsigned short));
				memcpy(pID, recvbuf, sizeof(unsigned short));
				int m = ntohs(*pID);
				unsigned short oID = htons(IDTransTable[m].oldID);
				memcpy(recvbuf, &oID, sizeof(unsigned short));
				IDTransTable[m].done = TRUE;

				//从ID转换表中获取发出DNS请求者的信息
				clientName = IDTransTable[m].client;

				//把recvbuf转发至请求者处
				iSend = sendto(socketLocal, recvbuf, iRecv, 0, (SOCKADDR*)&clientName, sizeof(clientName));
				if (iSend == SOCKET_ERROR) {
					cout << "sendto Failed: " << WSAGetLastError() << endl;
					continue;
				}
				else if (iSend == 0)
					break;

				free(pID);	//释放动态分配的内存
			}
			//在域名解析表中找到 
			else {	
				//获取请求报文的ID
				unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
				memcpy(pID, recvbuf, sizeof(unsigned short));

				//转换ID
				unsigned short nID = RegisterNewID(ntohs(*pID), clientName, FALSE);

				//打印 时间 newID 功能 域名 IP
				DisplayInfo(nID, find);

				//构造响应报文返回
				memcpy(sendbuf, recvbuf, iRecv);						//拷贝请求报文
				unsigned short a = htons(0x8180);
				memcpy(&sendbuf[2], &a, sizeof(unsigned short));		//修改标志域

				//修改回答数域
				if (strcmp(DNS_table[find].IP.c_str(), "0.0.0.0") == 0)	
					a = htons(0x0000);	//屏蔽功能：回答数为0
				else
					a = htons(0x0001);	//服务器功能：回答数为1
				memcpy(&sendbuf[6], &a, sizeof(unsigned short));
				int curLen = 0;

				//构造DNS响应部分
				char answer[16];
				unsigned short Name = htons(0xc00c);
				memcpy(answer, &Name, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned short TypeA = htons(0x0001);
				memcpy(answer+curLen, &TypeA, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned short ClassA = htons(0x0001);
				memcpy(answer+curLen, &ClassA, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned long timeLive = htonl(0x7b);
				memcpy(answer+curLen, &timeLive, sizeof(unsigned long));
				curLen += sizeof(unsigned long);

				unsigned short IPLen = htons(0x0004);
				memcpy(answer+curLen, &IPLen, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned long IP = (unsigned long) inet_addr(DNS_table[find].IP.c_str());
				memcpy(answer+curLen, &IP, sizeof(unsigned long));
				curLen += sizeof(unsigned long);
				curLen += iRecv;

				//请求报文和响应部分共同组成DNS响应报文存入sendbuf
				memcpy(sendbuf+iRecv, answer, curLen);

				//发送DNS响应报文
				iSend = sendto(socketLocal, sendbuf, curLen, 0, (SOCKADDR*)&clientName, sizeof(clientName));
				if (iSend == SOCKET_ERROR) {
					cout << "sendto Failed: " << WSAGetLastError() << endl;
					continue;
				}
				else if (iSend == 0)
					break;
			
				free(pID);		//释放动态分配的内存
			}
		} 
	}

    closesocket(socketServer);	//关闭套接字
	closesocket(socketLocal);
    WSACleanup();				//释放ws2_32.dll动态链接库初始化时分配的资源

    return 0;
}
