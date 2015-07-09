/*******************************************************************************
 *                                                                             *
 * resbash.c - Resolver basher                                                 *
 *                                                                             *
 * DESCRIPTION                                                                 *
 * Resbash - Designed to hit a resolver hard with queries                      *
 * We want to trigger the resolver to do validation. We are not interested in  *
 * replies. The idea is that the resolver will log servfail's, if they occur,  *
 * and that we will use that logging.                                           *
 *                                                                             *
 * Adapted by:                                                                 *
 *   Marco Davids - SIDN Labs                                                  *
 * Based on:                                                                   *
 *   dnsdrdos from noptrix                                                     *
 *                                                                             *
 * DISCLAIMER                                                                  *
 * - Quick'n'dirty code                                                        *
 * - No liability, no warranty                                                 *
 * - Only for testing purposes. Author is not responsible for misusage!        *
 *                                                                             *
 * VERSION                                                                     *
 * 20150408                                                                    *
 *                                                                             *
 ******************************************************************************/

// TODO:
// [WONTFIX] trailing-dot in domains.lst file, or hardcoded here?
//
// Beter input validation on domainnames (label-length etc)
//
// Perhaps: IPv6 ?
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


/* global settings */
#define VERSION             "v0.1edns"
#define ATOI(x)             strtol(x, (char **) NULL, 10)
#define MAX_LEN             128     /* max line for dns reslver list */


/* default settings */
#define DEFAULT_RES_ADDR    "127.0.0.1"
#define DEFAULT_DNS_PORT    5353
#define DEFAULT_LOOPS       1
#define DEFAULT_RATELIMIT   1000 /* microseconds */
#define DEFAULT_QTYPE       48 /* DNSKEY */


/* error handling */
#define __EXIT_FAILURE      exit(EXIT_FAILURE);
#define __EXIT_SUCCESS      exit(EXIT_SUCCESS);

#define __ERR_GEN do { fprintf(stderr,"[-] ERROR: " __FILE__ ":%u -> ",\
                               __LINE__); fflush(stderr); perror(""); \
    __EXIT_FAILURE } while (0)


/* dns header */
typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} dnsheader_t;


/* dns query */
typedef struct {
    unsigned short qtype;
    unsigned short qclass;
    
    unsigned char additional[11];

} query_t;


/* our job */
typedef struct {
    char *file;
    char *res_addr;
    uint16_t port;
    unsigned int num_domains;
    char **domains;
    unsigned int loops;
    unsigned short qtype;
    useconds_t delay;
} job_t;


/* our bomb */
typedef struct {
    int one;
    int sock;
    char *packet;
    struct sockaddr_in target;
    struct iphdr *ip;
    struct udphdr *udp;
    dnsheader_t *dns;
    query_t *query;
} bomb_t;


/* just wrapper */
void *xmalloc(size_t);
void *xmemset(void *, int, size_t);
int xsocket(int, int, int);
void xclose(int);
void xsendto(int, const void *, size_t, int, const struct sockaddr *,
             socklen_t);

/* prog stuff */
void banner();
void usage();
void check_argc(int);
void check_args();
FILE *open_file(char *);
unsigned int count_lines(char *);
char **read_lines(char *, unsigned int);
void check_uid();

/* net stuff */
bomb_t *create_rawsock(bomb_t *);
bomb_t *stfu_kernel(bomb_t *);
unsigned short checksum(unsigned short *, int);
bomb_t *build_ip_header(bomb_t *, job_t *,int);
bomb_t *build_udp_header(bomb_t *, job_t *,int);
bomb_t *build_dns_request(bomb_t *, job_t *,int);
void dns_name_format(char *, char *);
bomb_t *build_packet(bomb_t *, job_t *, int);
bomb_t *fill_sockaddr(bomb_t *);
void run_resbash(job_t *, int);
void free_resbash(job_t *);


/* wrapper for malloc() */
void *xmalloc(size_t size)
{
   void *buff;


   if ((buff = malloc(size)) == NULL) {
       __ERR_GEN;
   }

   return buff;
}


/* wrapper for memset() */
void *xmemset(void *s, int c, size_t n)
{
   if (!(s = memset(s, c, n))) {
       __ERR_GEN;
   }

   return s;
}


/* wrapper for socket() */
int xsocket(int domain, int type, int protocol)
{
    int sockfd = 0;


    sockfd = socket(domain, type, protocol);

    if (sockfd == -1) {
        __ERR_GEN;
    }

    return sockfd;
}


/* wrapper for setsockopt() */
void xsetsockopt(int sockfd, int level, int optname, const void *optval,
                 socklen_t optlen)
{
    int x = 0;


    x = setsockopt(sockfd, level, optname, optval, optlen);

    if (x != 0) {
        __ERR_GEN;
    }

    return;
}


/* wrapper for close() */
void xclose(int fd)
{
    int x = 0;


    x = close(fd);

    if (x != 0) {
        __ERR_GEN;
    }

    return;
}


/* wrapper for sendto() */
void xsendto(int sockfd, const void *buf, size_t len, int flags,
             const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int x = 0;

    
    x = sendto(sockfd, buf, len, flags, dest_addr, addrlen);

    if (x == -1) {
        __ERR_GEN;
    }

    return;
}


/* just our leet banner */
void banner()
{
    printf("---------------------------------------\
    \nresbash - For SIDN Labs                \
    \n---------------------------------------\n");

    return;
}


/* usage and help */
void usage()
{
    printf("usage:\n\n\
  resbash -d <file> [options] | [misc]\n\
    \ntarget:\n\n\
  -r <addr>       - IPv4 address of dns resolver (default: 127.0.0.1)\n\
  -d <file>       - list of domains that should be queries (on per line!)\n\
  -l <num>        - how many loops through domains list? (default: 1)\n\
  -t <num>        - Numerical querytype (default: 48, is DNSKEY)\n\
  -q <num>        - Qps (theoretical max: 1000000, min: 1, default: 1000)\n\nmisc:\n\n\
  -V              - show version\n\
  -H              - show help and usage\n\nexample:\n\n\
  ./resbash -d dnssecsigneddomains.lst\n\n\
  or:\n\n\
  $ for i in `seq 1 100`; do ./resbash -r 192.168.10.$i -d domainslist-$i.lst &; done\n\n");

    __EXIT_SUCCESS;

    return;
}


/* check first usage */
void check_argc(int argc)
{
    if (argc < 2) {
        fprintf(stderr, "[-] ERROR: use -H for help and usage\n");
        __EXIT_FAILURE;
    }

    return;
}


/* check if host and port are selected */
/* TODO: Could be improved, especially delay (if it is -1 for example) */
void check_args(job_t *job)
{
    if (!(job->file) || !(job->res_addr) || (job->loops <= 0) || (job->delay < 1) ) {
        fprintf(stderr, "[-] ERROR: you f*cked up, mount /dev/brain\n");
        __EXIT_FAILURE
    }

    return;
}


/* open file and return file pointer */
FILE *open_file(char *file)
{
    FILE *fp = NULL;


    if (!(fp = fopen(file, "r"))) {
        __ERR_GEN;
    }

    return fp;
}


/* count lines -> wc -l :) */
unsigned int count_lines(char *file)
{
    FILE *fp = NULL;
    int c = 0;
    unsigned int lines = 0;


    fp = open_file(file);

    while ((c = fgetc(fp)) != EOF) {
        if ((c == '\n') || (c == 0x00)) {
            lines++;
        }
    }
    fclose(fp);

    return lines;
}


/* read in domains line by line */
char **read_lines(char *file, unsigned int lines)
{
    FILE *fp = NULL;
    char *buffer = NULL;
    char **words = NULL;
    int i = 0;


    fp = open_file(file);

    buffer = (char *) xmalloc(MAX_LEN);
    words = (char **) xmalloc(lines * sizeof(char *));
    buffer = xmemset(buffer, 0x00, MAX_LEN);

    while (fgets(buffer, MAX_LEN, fp) != NULL) {
        if ((buffer[strlen(buffer) - 1] == '\n') ||
            (buffer[strlen(buffer) - 1] == '\r')) {
            buffer[strlen(buffer) - 1] = 0x00;
            words[i] = (char *) xmalloc(MAX_LEN - 1);
            words[i] = xmemset(words[i], 0x00, MAX_LEN - 1);
            strncpy(words[i], buffer, MAX_LEN - 1);
            buffer = xmemset(buffer, 0x00, MAX_LEN - 1);
            i++;
        } else {
            continue;
        }
    }
    free(buffer);
    fclose(fp);

    return words;
}


/* set default values */
job_t *set_defaults()
{
    job_t *job;


    job = (job_t *) xmalloc(sizeof(job_t));
    job = xmemset(job, 0x00, sizeof(job_t));

    job->res_addr = DEFAULT_RES_ADDR;
    job->port = (uint16_t) DEFAULT_DNS_PORT;
    job->loops = (unsigned int) DEFAULT_LOOPS;
    job->qtype = (unsigned short) DEFAULT_QTYPE;
    job->delay = (useconds_t) DEFAULT_RATELIMIT;

    return job;
}


/* check for uid */
void check_uid()
{
    if (getuid() != 0) {
        fprintf(stderr, "[-] ERROR: you need to be r00t\n");
        __EXIT_FAILURE;
    }

    return;
}


/* create raw socket */
bomb_t *create_rawsock(bomb_t *bomb)
{
    bomb->sock = xsocket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    return bomb;
}


/* say STFU to kernel - we set our own headers */
bomb_t *stfu_kernel(bomb_t *bomb)
{
    bomb->one = 1;

    xsetsockopt(bomb->sock, IPPROTO_IP, IP_HDRINCL, &bomb->one, 
                sizeof(bomb->one));

    return bomb;
}


/* checksum for IP and UDP header */
unsigned short checksum(unsigned short *addr, int len)
{
    u_int32_t cksum  = 0;
    
    
    while(len > 0) {
        cksum += *addr++;
        len -= 2;
    }

    if(len == 0) {
        cksum += *(unsigned char *) addr;
    }
    
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = cksum + (cksum >> 16);

    return (~cksum);
}


/* build and fill in ip header */
bomb_t *build_ip_header(bomb_t *bomb, job_t *job, int c)
{

    char spoof_addr[16]; /* TODO: not too small? */
    sprintf(spoof_addr, "127.%d.%d.%d", rand() % 254 + 1, rand() % 254 + 1, rand() % 254 + 1);
    /* 127.255.255.255 or 127.0.0.0 might be undesirable */ 
    
    bomb->ip = (struct iphdr *) bomb->packet;

    bomb->ip->version = 4;
    bomb->ip->ihl = 5;
    bomb->ip->id = htonl(rand());
    bomb->ip->saddr = inet_addr(spoof_addr);
    bomb->ip->daddr = inet_addr(job->res_addr);
    bomb->ip->ttl = 64;
    bomb->ip->tos = 0;
    // http://www.gossamer-threads.com/lists/engine?do=post_attachment;postatt_id=1943;list=nanog
    bomb->ip->frag_off |= (htons(1<<15));
    bomb->ip->protocol = IPPROTO_UDP;
    bomb->ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
                              sizeof(dnsheader_t) + sizeof(query_t) +
                              strlen(job->domains[c]) + 1);
    bomb->ip->check = checksum((unsigned short *) bomb->ip,
                               sizeof(struct iphdr));

    return bomb;
}


/* build and fill in udp header */
bomb_t *build_udp_header(bomb_t *bomb, job_t *job,int c)
{
    bomb->udp = (struct udphdr *) (bomb->packet + sizeof(struct iphdr));

    bomb->udp->source = htons(rand()); /* UDP source port */
    bomb->udp->dest = htons(DEFAULT_DNS_PORT);
    bomb->udp->len = htons(sizeof(struct udphdr) + sizeof(dnsheader_t) +
                           sizeof(query_t) + strlen(job->domains[c]) + 1);
    bomb->udp->check = 0;

    return bomb;
}


/* convert to dns format */
void dns_name_format(char *qname, char *host)
{
    int i = 0;
    int j = 0;

    
    for (i = 0 ; i < (int) strlen(host) ; i++) {
        if (host[i] == '.') {
            *qname++ = i-j;
            for (; j < i; j++) {
                *qname++ = host[j];
            }
            j++;
        }
    }

    *qname++ = 0x00;
}


/* build and fill in dns request */
bomb_t *build_dns_request(bomb_t *bomb, job_t *job, int c)
{
    char *qname = NULL;


    bomb->dns = (dnsheader_t *) (bomb->packet + sizeof(struct iphdr) + 
                           sizeof(struct udphdr));

//    bomb->dns->id = (unsigned short) htons(getpid());
    bomb->dns->id = htons(rand()); /* TODO: strange, always starts with 0x9869...? */
    bomb->dns->qr = 0;
    bomb->dns->opcode = 0;
    bomb->dns->aa = 0;
    bomb->dns->tc = 0;
    bomb->dns->rd = 1;
    bomb->dns->ra = 0;
    bomb->dns->z = 0;
    bomb->dns->ad = 0; /* It could also be 1 https://tools.ietf.org/html/rfc6840#section-5.7 */
    bomb->dns->cd = 0;
    bomb->dns->rcode = 0;
    bomb->dns->q_count = htons(1);
    bomb->dns->ans_count = 0;
    bomb->dns->auth_count = 0;
    bomb->dns->add_count = htons(1);

    qname = &bomb->packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 
        sizeof(dnsheader_t)];

    dns_name_format(qname, job->domains[c]);

    bomb->query = (query_t *) &bomb->packet[sizeof(struct iphdr) + 
        sizeof(struct udphdr) + sizeof(dnsheader_t) + (strlen(qname) + 1)];

    bomb->query->qtype = htons(job->qtype);
    bomb->query->qclass = htons(1);
    
    /* let's do EDNS with UDP size 4096 and DO-bit set */
    memcpy(&bomb->query->additional, "\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00",11);

    return bomb;
    
}


/* build packet */
bomb_t *build_packet(bomb_t *bomb, job_t *job, int c)
{
    bomb->packet = (char *) xmalloc(1400);
    bomb->packet = xmemset(bomb->packet, 0x00, 1400);

    bomb = build_ip_header(bomb, job,c);
    bomb = build_udp_header(bomb, job,c);
    bomb = build_dns_request(bomb, job,c);

    return bomb;
}


/* fill in sockaddr_in {} */
bomb_t *fill_sockaddr(bomb_t *bomb)
{
    bomb->target.sin_family = AF_INET;
    bomb->target.sin_port = bomb->udp->dest;
    bomb->target.sin_addr.s_addr = bomb->ip->daddr;

    return bomb;
}


/* start action! */
void run_resbash(job_t *job, int c)
{
    bomb_t *bomb = NULL;

    
    bomb = (bomb_t *) xmalloc(sizeof(bomb_t));
    bomb = xmemset(bomb, 0x00, sizeof(bomb_t));

    bomb = create_rawsock(bomb);
    bomb = stfu_kernel(bomb);
    bomb = build_packet(bomb, job, c);
    bomb = fill_sockaddr(bomb);

    xsendto(bomb->sock, bomb->packet, sizeof(struct iphdr) + 
            sizeof(struct udphdr) + sizeof(dnsheader_t) + sizeof(query_t) + 
            strlen(job->domains[c]) + 1, 0, (struct sockaddr *) &bomb->target, 
            sizeof(bomb->target));

    xclose(bomb->sock);
    free(bomb->packet);
    free(bomb);

    return;
}


/* free resbash \o/ */
void free_resbash(job_t *job)
{
    int i = 0;

    for (i = 0; i < job->num_domains; i++) {
        free(job->domains[i]);
    }

    free(job);

    return;
}


/* here we go */
int main(int argc, char **argv)
{
    int c = 0;
    unsigned int i = 0;
    job_t *job;


    banner();           /* banner output is important! */
    check_argc(argc);
    job = set_defaults();

    while ((c = getopt(argc, argv, "d:l:t:q:VH")) != -1) {
        switch (c) {
         case 'd':
             job->file = optarg;
             break;
         case 'l':
             job->loops = (unsigned int) ATOI(optarg);
             break;
         case 't':
             job->qtype = (unsigned short) ATOI(optarg);
             break;    
         case 'q':
             if (ATOI(optarg) == 0) {
                job->delay = 0;
             }
             else {
                job->delay = (useconds_t) 1000000 / ATOI(optarg);
             };
             break;
         case 'V':
             puts(VERSION);
             __EXIT_SUCCESS;
             break;
         case 'H':
             usage();
             break;
             __EXIT_SUCCESS;
        }
    }

    check_args(job);
    
    job->num_domains = count_lines(job->file);
    job->domains = read_lines(job->file, job->num_domains);
    
    check_uid();
    
    for (i = 0; i < job->loops; i++) {
        for (c = 0; c < job->num_domains; c++) {
            run_resbash(job, c);
            usleep (job->delay);
        }
    }
    printf("\n");
    
    free_resbash(job);
    
    return 0;
}

/* EOF */
