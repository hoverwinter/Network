#include "router.h"
IfInfo_t IfInfo[MAX_IF];
int IfCount;
RouteTable_t RouteTable[100];
int RouteCount;
IP_MAC_t IP_MAC[100];
int IP_MACCount;
vector<SendPacket_t> SP;
pthread_mutex_t sq_mutex;

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *a;
    ip_t ipaddr;
    RouteTable_t rt;
    int i,j,k;

    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地机器设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error: in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    //打印列表
    i = j = k = 0;
    for(d=alldevs; d ; d= d->next)
    {
        if(d->addresses)
        {
            IfInfo[i].ipnums = 0;
            strcpy(IfInfo[i].desc, d->description);
            strcpy(IfInfo[i].name, d->name);
            for(a=d->addresses; a; a=a->next)
            {
                if (a->addr->sa_family == AF_INET)
                {
                    ipaddr.addr = (((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
                    ipaddr.mask = (((struct sockaddr_in*)a->netmask)->sin_addr.s_addr);
                    IfInfo[i].ip[IfInfo[i].ipnums++] = ipaddr;
                    j++;
                }
            }
            if(i==MAX_IF) break;
            else	i++;
        }
    }
    //实际接口数
    IfCount = i;
    // 显示
    showIfInfos();
    // 至少拥有两个IP地址
    if(j<2)
    {
        fprintf(stderr, "Error: IP addr should be at least 2!");
        exit(1);
    }
    //打开接口
    for (i=0; i < IfCount; i++)
    {
        if ( (IfInfo[i].adhandle = pcap_open(IfInfo[i].name, // 设备名
                                             65536, // 最大包长度
                                             PCAP_OPENFLAG_PROMISCUOUS,// 混杂模式
                                             1000, // 超时时间
                                             NULL, // 远程认证
                                             errbuf // 错误缓存
                                            ) ) == NULL)
        {
            // 错误，显示错误信息
            fprintf(stderr, "Error: fail to open interface %s!", IfInfo[i].name);
            exit(-1);
        }
    }
    // 捕获本机MAC地址
    int res;
    pthread_t pid;
    for (i = 0; i < IfCount; i++)
    {
        res  = pthread_create(&pid, NULL,CaptureLocalARP,&IfInfo[i] );
        if(res!=0)
        {
            fprintf(stderr, "Error: fail to create thread!");
            exit(-1);
        }
    }
    u_char srcMAC[6];
    u_long srcIP;
    // 将列表中网卡硬件地址清 0
    for (i = 0; i < IfCount; i++)
    {
        setMAC(IfInfo[i].mac, 0);
    }
// 为得到真实网卡地址，使用虚假的 MAC 地址和 IP 地址向本机发送 ARP 请求
    setMAC(srcMAC, 66); // 设置虚假的 MAC 地址
    srcIP = inet_addr("112.112.112.112"); // 设置虚假的 IP 地址
    for (i = 0; i < IfCount; i++)
    {
        ARPRequest(IfInfo[i].adhandle, srcMAC, srcIP, IfInfo[i].ip[WORK_IP].addr);
    }
// 确保所有接口的 MAC 地址完全收到
    setMAC(srcMAC, 0);
    do
    {
        Sleep(1000);
        k = 0;
        for (i = 0; i < IfCount; i++)
        {
            if (!cmpMAC(IfInfo[i].mac, srcMAC))
            {
                k++;
                continue;
            }
            else
            {
                break;
            }
        }
    }
    while (!((j++ > 10) || (k == IfCount)));
    if (k != IfCount)
    {
        printf("Error: at least one MAC addr not obtained!");
        exit(-1);
    }
    //不再需要设备列表了，释放它
    pcap_freealldevs(alldevs);

    showIfInfos();

    // 初始化路由表并显示
    RouteCount = 0;
    for (i = 0; i < IfCount; i++)
    {
        for (j = 0; j < IfInfo[i].ipnums; j++)
        {
            rt.IfNo = i;
            rt.DstIP = IfInfo[i].ip[j].addr & IfInfo[i].ip[j].mask;
            rt.Mask = IfInfo[i].ip[j].mask;
            rt.NextHop = 0; // 直接投递
            RouteTable[RouteCount++] = rt;
        }
    }
    showRouteTables();
    // 提示用户建立新的路由表

    // 设置过滤规则:仅仅接收 arp 响应帧和需要路由的帧
    struct bpf_program fcode;
    string Filter, Filter0, Filter1;
    Filter0  = '(';
    Filter1  = '(';
    for (i = 0; i < IfCount; i++)
    {
        Filter0 += "(ether dst " + string(mactos(IfInfo[i].mac)) + ")";
        for (j = 0; j < IfInfo[i].ipnums; j++)
        {
            Filter1 += "(ip dst host " + string(iptos(IfInfo[i].ip[j].addr)) + ")";
            if (((j == (IfInfo[i].ipnums-1))) && (i == (IfCount-1)))
            {
                Filter1 += ")";
            }
            else
            {
                Filter1 += " or ";
            }
        }
        if (i == (IfCount-1))
        {
            Filter0 += ")";
        }
        else
        {
            Filter0 += " or ";
        }
    }
    Filter = Filter0 + " and ((arp and (ether[21]=0x2)) or (not" + Filter1 + "))";
	cout<<"================Filter Rules============="<<endl<<Filter<<endl<<"================================="<<endl;

    for (i = 0; i < IfCount; i++)
    {
        if (pcap_compile(IfInfo[i].adhandle , &fcode, Filter.c_str(), 1,  IfInfo[i].ip[0].mask) <0 )
        {
            fprintf(stderr,"Error: failure when setting the filter rules, please check the syntax!");
            exit(-1);
        }
        if (pcap_setfilter(IfInfo[i].adhandle, &fcode)<0)
        {
        	fprintf(stderr, "Error: unable to set the filter rules!");
        	exit(-1);
        }
    }
    // 设置互斥锁
    pthread_mutex_init(&sq_mutex, NULL);
    // 开始捕获数据包
    pthread_t cap_thds[IfCount];
    for (i=0; i < IfCount; i++)
    {
        res  = pthread_create(&cap_thds[i], NULL,Capture,&IfInfo[i] );
        if(res!=0)
        {
            fprintf(stderr, "Error: fail to create thread!");
            exit(-1);
        }
    }
    // 等待线程完成
    for(i=0; i< IfCount; i++)
        pthread_join(cap_thds[i],NULL);
    return 0;
}
