struct myarphdr
{
    unsigned short hw_type;           /* hardware address */
    unsigned short protocol_type;             /* protocol address */
    unsigned char hw_addr_len;       /* length of hardware address */
    unsigned char protocol_addr_len;         /* length of protocol address */
    unsigned short opcode;      /*operate code 1 ask 2 reply*/
    unsigned char src_mac[6];
    struct in_addr src_ip;
    unsigned char dst_mac[6];
    struct in_addr dst_ip;
    unsigned char padding[18];
};



