#include "router.h"
extern IfInfo_t IfInfo[MAX_IF];
extern int IfCount;
extern RouteTable_t RouteTable[100];
extern int RouteCount;
extern IP_MAC_t IP_MAC[100];
extern int IP_MACCount;
extern vector<SendPacket_t> SP;
extern pthread_mutex_t sq_mutex;

// 设置MAC地址
void setMAC(u_char *MAC, u_char ch)
{
    int i;
    for (i=0; i<6; i++)
    {
        MAC[i] = ch;
    }
    return;
}
// 发送ARP请求
void ARPRequest(pcap_t *adhandle, u_char *srcMAC, u_long srcIP, u_long targetIP)
{
    ARPFrame_t ARPFrame;
    int i;
    for (i=0; i<6; i++)
    {
        ARPFrame.FrameHeader.DesMAC[i] = 255;
        ARPFrame.FrameHeader.SrcMAC[i] = srcMAC[i];
        ARPFrame.SendHa[i] = srcMAC[i];
        ARPFrame.RecvHa[i] = 0;
    }
    ARPFrame.FrameHeader.FrameType = htons(0x0806);
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800);
    ARPFrame.HLen = 6;
    ARPFrame.PLen = 4;
    ARPFrame.Operation = htons(0x0001);
    ARPFrame.SendIP = srcIP;
    ARPFrame.RecvIP = targetIP;
    if(pcap_sendpacket(adhandle, (u_char *) &ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        fprintf(stderr,"Error: send ARP Request Failed!\n");
    }
}

// 比较MAC地址是否相等
int cmpMAC(u_char *MAC1, u_char *MAC2)
{
    int i;
    for ( i=0; i<6; i++)
    {
        if (MAC1[i]==MAC2[i])
        {
            continue;
        }
        else
        {
            return 0;
        }
    }
    return 1;
}

//将数字类型的IP地址转换成字符串类型的
#define IPTOSBUFFERS    MAX_IP_PER_IF
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;
    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

// MAC地址转成字符串类型
char* mactos(u_char * nMACAddr)
{
    static char strbuf[50];
    sprintf(strbuf,"%02X:%02X:%02X:%02X:%02X:%02X", nMACAddr[0],
            nMACAddr[1],
            nMACAddr[2], nMACAddr[3], nMACAddr[4], nMACAddr[5]);
    return strbuf;
}

// 捕获本地ARP请求
void* CaptureLocalARP(void* pParam)
{
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    IfInfo_t *pIfInfo;
    ARPFrame_t *ARPFrame;
    pIfInfo = (IfInfo_t *)pParam;
    while (1)
    {
        Sleep(50);
        res = pcap_next_ex( pIfInfo->adhandle , &header, &pkt_data);
        // 超时
        if (res == 0)
            continue;
        if (res > 0)
        {
            ARPFrame = (ARPFrame_t *) (pkt_data);
            // 得到本接口的 MAC 地址
            if ((ARPFrame->FrameHeader.FrameType == htons(0x0806))
                    && (ARPFrame->Operation == htons(0x0002))
                    && (ARPFrame->SendIP == pIfInfo->ip[WORK_IP].addr))
            {
                cpyMAC(pIfInfo->mac, ARPFrame->SendHa);
                pthread_exit(NULL);
                return NULL;
            }
        }
    }
}

// 复制MAC地址
void cpyMAC(u_char *MAC1, u_char *MAC2)
{
    int i;
    for (i=0; i<6; i++)
    {
        MAC1[i]=MAC2[i];
    }
}

//显示所有适配器接口
void showIfInfos()
{
    int i,j;
    for(i=0; i<IfCount; i++)
    {
        printf("==========Adapter %d============\n",i);
        printf("Name:  %s\nDescription:  %s\n", IfInfo[i].name, IfInfo[i].desc);
        for(j=0; j<IfInfo[i].ipnums; j++)
        {
            printf(" IPAddr:  %s\n Netmask:  %s\n", iptos(IfInfo[i].ip[j].addr), iptos(IfInfo[i].ip[j].mask));
            printf(" MAC:  %s\n", mactos(IfInfo[i].mac));
        }
    }
    printf("==============================\n");
}

//显示路由表
void showRouteTables()
{
    int i;
    printf("==========Route Table============\n");
    for(i=0; i<RouteCount; i++)
    {
        printf("%d  %s  %s  %s\n",RouteTable[i].IfNo, iptos(RouteTable[i].Mask), iptos(RouteTable[i].DstIP), iptos(RouteTable[i].NextHop));
    }
    printf("==============================\n");
}


// 数据包捕获线程
void* Capture(void* pParam)
{
    int res;
    IfInfo_t *pIfInfo;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    ARPFrame_t *ARPf;
    IPFrame_t *IPf;
    pIfInfo = (IfInfo_t *)pParam;
    // 开始正式接收并处理帧
    while (1)
    {
        res = pcap_next_ex( pIfInfo->adhandle, &header, &pkt_data);
        if (res == 1)
        {
            FrameHeader_t *fh;
            fh = (FrameHeader_t *) pkt_data;
            switch (ntohs(fh->FrameType))
            {
            case 0x0806:

                ARPf = (ARPFrame_t *)pkt_data;
                // ARP 包，转到 ARP 包处理函数
                ARPPacketProc(header, pkt_data);
                break;
            case 0x0800:

                IPf = (IPFrame_t*) pkt_data;
                // IP 包，转到 IP 包处理函数
                IPPacketProc(pIfInfo, header, pkt_data);
                break;
            default:
                break;
            }
        }
        else if (res == 0) // 超时
        {
            continue;
        }
        else
        {
            fprintf(stderr, "Error：pcap_next_ex failed!");
        }
    }
    return NULL;
}
// 处理 ARP 数据包

void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data)
{
    int flag;
    ARPFrame_t ARPf;
    IPFrame_t *IPf;
    SendPacket_t sPacket;
    IP_MAC_t ip_mac;
    u_char macAddr[6];
    ARPf = *(ARPFrame_t *)pkt_data;
    if (ARPf.Operation == ntohs(0x0002))
    {
        printf("Received ARP Response: %s  --  %s\n", iptos(ARPf.SendIP),  mactos(ARPf.SendHa));
        // IP－ MAC 地址映射表中已经存在该对应关系
        if (IPLookup(ARPf.SendIP, macAddr))
        {
        	printf(" The relationship is already in the IP-MAC table!\n");
            return;
        }
        else
        {
            ip_mac.IPAddr = ARPf.SendIP;
            memcpy(ip_mac.MACAddr, ARPf.SendHa, 6);
            // 将 IP-MAC 映射关系存入表中
            IP_MAC[IP_MACCount++] = ip_mac;
            // 日志输出信息
            printf(" Save the relationship into IP-MAC table!\n");
        }

        pthread_mutex_lock(&sq_mutex);
        do // 查看是否能转发缓存中的 IP 数据报
        {
            flag = 0;
            // 没有需要处理的内容
            if(SP.size()==0)
                break;
            // 遍历转发缓存区
            int i  ;
            for ( i=0; i < SP.size(); i++)
            {
                sPacket = SP[i];
                if (sPacket.TargetIP == ARPf.SendIP)
                {
                    IPf = (IPFrame_t *) sPacket.PktData;
                    cpyMAC(IPf->FrameHeader.DesMAC, ARPf.SendHa);
                    int t;
                    for(t=0; t<6; t++)
                    {
                        IPf->FrameHeader.SrcMAC[t] = IfInfo[sPacket.IfNo].mac[t];
                    }
                    // 发送 IP 数据包
                    pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char*) sPacket.PktData, sPacket.len);
                    SP.erase(SP.begin()+i);
                    // 日志输出信息
					printf("  Forwarding the IP datagram whose DST addr is the received MAC:\n\t %s  -> %s \n \t%s -> ", iptos(IPf->IPHeader.SrcIP), iptos(IPf->IPHeader.DstIP), mactos(IPf->FrameHeader.SrcMAC ));
					printf("%s\n", mactos(IPf->FrameHeader.DesMAC));
					flag = 1;
                    break;
                }
            }
        }
        while(flag);
        pthread_mutex_unlock(&sq_mutex);
    }
}
// 查询 IP-MAC 映射表
int IPLookup(u_long ipaddr, u_char *p)
{
    IP_MAC_t ip_mac;
    int pos;
    if (IP_MACCount == 0) return 0;
    pos = 0;
    int i,j;
    for ( i = 0; i<IP_MACCount; i++)
    {
        ip_mac = IP_MAC[i];
        if (ipaddr == ip_mac.IPAddr)
        {
            for ( j = 0; j < 6; j++)
            {
                p[j] = ip_mac.MACAddr[j];
            }
            return 1;
        }
    }
    return 0;
}
// 处理 IP 数据包
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char
                  *pkt_data)
{
    IPFrame_t *IPf;
    SendPacket_t sPacket;
    IPf = (IPFrame_t *) pkt_data;
    printf("Received IP Datagram: %s  ->  %s\n", iptos(IPf->IPHeader.SrcIP), iptos(IPf->IPHeader.DstIP));
// ICMP 超时
    if (IPf->IPHeader.TTL <= 0)
    {
        ICMPPacketProc(pIfInfo, 11, 0, pkt_data);
        return;
    }
    IPHeader_t *IpHeader = &(IPf->IPHeader);
// ICMP 差错
    if (IsChecksumRight((char *)IpHeader) == 0)
    {
// 日志输出信息
		fprintf(stderr, "  Error: checksum of IP datagram is wrong, abandoned!\n");
        return;
    }
// 路由查询
    u_long nextHop; // 经过路由选择算法得到的下一站目的 IP 地址
    u_int ifNo; // 下一跳的接口序号
// 路由查询
    if((nextHop = RouteLookup(&ifNo, IPf->IPHeader.DstIP)) == -1)
    {
        // ICMP 目的不可达
        ICMPPacketProc(pIfInfo, 3, 0, pkt_data);
        return;
    }
    else
    {
        sPacket.IfNo = ifNo;
        sPacket.TargetIP = nextHop;
        cpyMAC(IPf->FrameHeader.SrcMAC, IfInfo[sPacket.IfNo].mac);
// TTL 减 1
        IPf->IPHeader.TTL -= 1;
        unsigned short check_buff[sizeof(IPHeader_t)];
// 设 IP 头中的校验和为 0
        IPf->IPHeader.Checksum = 0;
        memset(check_buff, 0, sizeof(IPHeader_t));
        IPHeader_t * ip_header = &(IPf->IPHeader);
        memcpy(check_buff, ip_header, sizeof(IPHeader_t));
// 计算 IP 头部校验和
        IPf->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
// IP-MAC 地址映射表中存在该映射关系
        if (IPLookup(sPacket.TargetIP, IPf->FrameHeader.DesMAC))
        {
            memcpy(sPacket.PktData, pkt_data, header->len);
            sPacket.len = header->len;
            if(pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *)
                               sPacket.PktData, sPacket.len) != 0)
            {
// 错误处理
				fprintf(stderr, "  Error during send IP datagram!\n");
                return;
            }
// 日志输出信息
            printf("  Forwarding the IP datagram: %s  -> %s \n \t%s -> ", iptos(IPf->IPHeader.SrcIP), iptos(IPf->IPHeader.DstIP), mactos(IPf->FrameHeader.SrcMAC ));
            printf("%s\n", mactos(IPf->FrameHeader.DesMAC));
        }
// IP-MAC 地址映射表中不存在该映射关系
        else
        {
            if (SP.size() < 65530) // 存入缓存队列
            {
                sPacket.len = header->len;
// 将需要转发的数据报存入缓存区
                memcpy(sPacket.PktData, pkt_data, header->len);
// 在某一时刻只允许一个线程维护链表
                pthread_mutex_lock(&sq_mutex);
                SP.push_back(sPacket);
                pthread_mutex_unlock(&sq_mutex);
// 日志输出信息
                printf(" DST MAC addr not found, save the IP datagram into the buffer!\n");
                printf("\tThe IP datagram is: %s  ->  %s \n \t%s -> xx:xx:xx:xx:xx:xx\n", iptos(IPf->IPHeader.SrcIP), iptos(IPf->IPHeader.DstIP), mactos(IPf->FrameHeader.SrcMAC));
                printf("Send ARP Request for DST MAC addr!\n");
// 发送 ARP 请求
                ARPRequest(IfInfo[sPacket.IfNo].adhandle,
                           IfInfo[sPacket.IfNo].mac,
                           IfInfo[sPacket.IfNo].ip[WORK_IP].addr, sPacket.TargetIP);
            }
            else // 如缓存队列太长，抛弃该报
            {
// 日志输出信息
                    printf(" Forward buffer is too long, IP datagram is abandoned!\n");
					printf("\tThe IP datagram is: %s  ->  %s \n \t%s -> xx:xx:xx:xx:xx:xx\n", iptos(IPf->IPHeader.SrcIP), iptos(IPf->IPHeader.DstIP), mactos(IPf->FrameHeader.SrcMAC));
            }
        }
    }
}
// 判断 IP 数据包头部校验和是否正确
int IsChecksumRight(char * buffer)
{
// 获得 IP 头内容
    IPHeader_t * ip_header = (IPHeader_t *)buffer;
// 备份原来的校验和
    unsigned short checksumBuf = ip_header->Checksum;
    unsigned short check_buff[sizeof(IPHeader_t)];
// 设 IP 头中的校验和为 0
    ip_header->Checksum = 0;
    memset(check_buff, 0, sizeof(IPHeader_t));
    memcpy(check_buff, ip_header, sizeof(IPHeader_t));
// 计算 IP 头部校验和
    ip_header->Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
// 与备份的校验和进行比较
    if (ip_header->Checksum == checksumBuf)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
// 查询路由表
u_long RouteLookup(u_int *ifNO, u_long desIP)
{
// desIP 为网络序
    u_long MaxMask = 0; // 获得最大的子网掩码的地址，没有获得时初始为-1
    int Index = -1; // 获得最大的子网掩码的地址对应的路由表索引，以便获得下一站路由器的地址
    int pos;
    RouteTable_t rt;
    u_long tmp;
    pos = 0;
    int i;
    for ( i=0; i < RouteCount; i++)
    {
        rt = RouteTable[i];
        if ((desIP & rt.Mask) == rt.DstIP)
        {
            Index = i;
            if(rt.Mask >= MaxMask)
            {
                *ifNO = rt.IfNo;
                if (rt.NextHop == 0) // 直接投递
                {
                    tmp = desIP;
                }
                else
                {
                    tmp = rt.NextHop;
                }
            }
        }
    }
    if(Index == -1) // 目的不可达
    {
        return -1;
    }
    else // 找到了下一跳地址
    {
        return tmp;
    }
}
// 发送 ICMP 数据包
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char
                    *pkt_data)
{
    u_char * ICMPBuf = new u_char[70];
// 填充帧首部
    memcpy(((FrameHeader_t *)ICMPBuf)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
    memcpy(((FrameHeader_t *)ICMPBuf)->SrcMAC, ((FrameHeader_t
            *)pkt_data)->DesMAC, 6);
    ((FrameHeader_t *)ICMPBuf)->FrameType = htons(0x0800);
// 填充 IP 首部
    ((IPHeader_t *)(ICMPBuf+14))->Ver_HLen = ((IPHeader_t
            *)(pkt_data+14))->Ver_HLen;
    ((IPHeader_t *)(ICMPBuf+14))->TOS = ((IPHeader_t
                                          *)(pkt_data+14))->TOS;
    ((IPHeader_t *)(ICMPBuf+14))->TotalLen = htons(56);
    ((IPHeader_t *)(ICMPBuf+14))->ID = ((IPHeader_t *)(pkt_data+14))->ID;
    ((IPHeader_t *)(ICMPBuf+14))->Flag_Segment = ((IPHeader_t
            *)(pkt_data+14))->Flag_Segment;
    ((IPHeader_t *)(ICMPBuf+14))->TTL = 64;
    ((IPHeader_t *)(ICMPBuf+14))->Protocol = 1;
    ((IPHeader_t *)(ICMPBuf+14))->SrcIP = ((IPHeader_t
                                            *)(pkt_data+14))->DstIP;
    ((IPHeader_t *)(ICMPBuf+14))->DstIP = ((IPHeader_t
                                            *)(pkt_data+14))->SrcIP;
    ((IPHeader_t *)(ICMPBuf+14))->Checksum =
        htons(ChecksumCompute((unsigned short *)(ICMPBuf+14),20));
// 填充 ICMP 首部
    ((ICMPHeader_t *)(ICMPBuf+34))->Type = type;
    ((ICMPHeader_t *)(ICMPBuf+34))->Code = code;
    ((ICMPHeader_t *)(ICMPBuf+34))->Id = 0;
    ((ICMPHeader_t *)(ICMPBuf+34))->Sequence = 0;
    ((ICMPHeader_t *)(ICMPBuf+34))->Checksum =
        htons(ChecksumCompute((unsigned short *)(ICMPBuf+34),8));
// 填充数据
    memcpy((u_char *)(ICMPBuf+42),(IPHeader_t *)(pkt_data+14),20);
    memcpy((u_char *)(ICMPBuf+62),(u_char *)(pkt_data+34),8);
// 发送数据包
    pcap_sendpacket(pIfInfo->adhandle, (u_char *)ICMPBuf, 70 );// 日志输出信息
    if (type == 11)
    {
        printf("Send ICMP timeout datagram!\n");
    }
    if (type == 3)
    {
        printf("Send ICMP destination address is not reachable datagram!\n");
    }
    printf(" ICMP -> %s  -   %s\n", iptos(((IPHeader_t *)(ICMPBuf+14))->DstIP), mactos(((FrameHeader_t *)ICMPBuf)->DesMAC));
    delete[] ICMPBuf;
}
// 计算校验和
unsigned short ChecksumCompute(unsigned short * buffer,int size)
{
// 32 位，延迟进位
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += * buffer++;
// 16 位相加
        size -= sizeof(unsigned short);
    }
    if(size)
    {
// 最后可能有单独 8 位
        cksum += *(unsigned char *)buffer;
    }
// 将高 16 位进位加至低 16 位
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
// 取反
    return (unsigned short)(~cksum);
}
