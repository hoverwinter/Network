#ifndef ROUTER_H_INCLUDED
#define ROUTER_H_INCLUDED

#include <vector>
#include <string>
#include <pcap.h>
#include <remote-ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <iostream>
#pragma pack(1)
#pragma comment(lib, "pthreadVC2.lib")  //必须加上这句
using namespace std;

typedef struct ip_t
{
    u_long addr;
    u_long mask;
} ip_t;

#define MAX_IP_PER_IF 5
#define WORK_IP 0
typedef struct IfInfo_t
{
    char name[100];
    char desc[100];
    u_char mac[6];
    ip_t ip[MAX_IP_PER_IF];
    int ipnums;
    pcap_t* adhandle;
} IfInfo_t;

typedef struct FrameHeader_t    // 帧首部
{
    UCHAR DesMAC[6];  // 目的地址
    UCHAR SrcMAC[6];  // 源地址
    USHORT FrameType;  // 帧类型
} FrameHeader_t;

typedef struct ARPFrame_t    // ARP 帧
{
    FrameHeader_t FrameHeader; // 帧首部
    USHORT HardwareType; // 硬件类型
    USHORT ProtocolType; // 协议类型
    BYTE HLen; // 硬件地址长度
    BYTE PLen; // 协议地址长度
    USHORT Operation; // 操作值
    UCHAR SendHa[6]; // 源 MAC 地址
    ULONG SendIP; // 源 IP 地址
    UCHAR RecvHa[6]; // 目的 MAC 地址
    ULONG RecvIP; // 目的 IP 地址
} ARPFrame_t;

typedef struct IPHeader_t    // IP 首部
{
    BYTE Ver_HLen;  // 版本+头部长度
    BYTE TOS; // 服务类型
    WORD TotalLen; // 总长度
    WORD ID; // 标识
    WORD Flag_Segment; // 标志+片偏移
    BYTE TTL; // 生存时间
    BYTE Protocol; // 协议
    WORD Checksum;  // 头部校验和
    ULONG SrcIP; // 源 IP 地址
    ULONG DstIP; // 目的 IP 地址
} IPHeader_t;

typedef struct ICMPHeader_t   // ICMP 首部
{
    BYTE Type; // 类型
    BYTE Code; // 代码
    WORD Checksum; // 校验和
    WORD Id; // 标识
    WORD Sequence; // 序列号
} ICMPHeader_t;

typedef struct IPFrame_t    // IP 帧
{
    FrameHeader_t FrameHeader; // 帧首部
    IPHeader_t IPHeader; // IP 首部
} IPFrame_t;

typedef struct SendPacket_t    // 发送数据包结构
{
    int len; // 长度
    BYTE PktData[2000];// 数据缓存
    ULONG TargetIP; // 目的 IP 地址
    UINT_PTR n_mTimer; // 定时器
    UINT IfNo; // 接口序号
} SendPacket_t;

typedef struct RouteTable_t    // 路由表结构
{
    u_long Mask; // 子网掩码
    u_long DstIP; // 目的地址
    u_long NextHop; // 下一跳步
    u_int IfNo; // 接口序号
} RouteTable_t;

typedef struct IP_MAC_t   // IP-MAC 地址映射结构
{
    ULONG IPAddr; // IP 地址
    UCHAR MACAddr[6]; // MAC 地址
} IP_MAC_t;

void showIfInfos();
void showRouteTables();
char *iptos(u_long in);
void* CaptureLocalARP(void* pParam);
char* mactos(u_char *nMACAddr);
void cpyMAC(u_char *MAC1, u_char *MAC2);
void setMAC(u_char *MAC, u_char ch);
void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP);
u_long RouteLookup(u_int *ifNO, u_long desIP);
unsigned short ChecksumCompute(unsigned short * buffer,int size);
void* Capture(void* pParam);
int cmpMAC(u_char *MAC1, u_char *MAC2);
void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data);
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data);
int IPLookup(u_long ipaddr, u_char *p);
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data);
int IsChecksumRight(char * buffer);

#define MAX_IF 5
#define QUEUE_LEN  20

#endif // ROUTER_H_INCLUDED
