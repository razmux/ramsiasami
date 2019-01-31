// Copyright (c) Athena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "cbasetypes.h"
#include "mmo.h"
#include "timer.h"
#include "malloc.h"
#include "showmsg.h"
#include "strlib.h"
#include "socket.h"

#include <stdlib.h>

#ifdef WIN32
	#include "winapi.h"
#else
	#include <errno.h>
#include <netinet/tcp.h>
	#include <net/if.h>
	#include <unistd.h>
#include <sys/ioctl.h>
	#include <netdb.h>
	#include <arpa/inet.h>

	#ifndef SIOCGIFCONF
	#include <sys/sockio.h> // SIOCGIFCONF on Solaris, maybe others? [Shinomori]
	#endif
	#ifndef FIONBIO
	#include <sys/filio.h> // FIONBIO on Solaris [FlavioJS]
	#endif

	#ifdef HAVE_SETRLIMIT
	#include <sys/resource.h>
	#endif
#endif

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// global array of sockets (emulating linux)
// fd is the position in the array
static SOCKET sock_arr[FD_SETSIZE];
static int sock_arr_len = 0;

/// Returns the socket associated with the target fd.
///
/// @param fd Target fd.
/// @return Socket
#define fd2sock(fd) sock_arr[fd]

/// Returns the first fd associated with the socket.
/// Returns -1 if the socket is not found.
///
/// @param s Socket
/// @return Fd or -1
int sock2fd(SOCKET s)
{
	int fd;

	// search for the socket
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == s )
			break;// found the socket
	if( fd == sock_arr_len )
		return -1;// not found
	return fd;
}


/// Inserts the socket into the global array of sockets.
/// Returns a new fd associated with the socket.
/// If there are too many sockets it closes the socket, sets an error and
//  returns -1 instead.
/// Since fd 0 is reserved, it returns values in the range [1,FD_SETSIZE[.
///
/// @param s Socket
/// @return New fd or -1
int sock2newfd(SOCKET s)
{
	int fd;

	// find an empty position
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == INVALID_SOCKET )
			break;// empty position
	if( fd == ARRAYLENGTH(sock_arr) )
	{// too many sockets
		closesocket(s);
		WSASetLastError(WSAEMFILE);
		return -1;
	}
	sock_arr[fd] = s;
	if( sock_arr_len <= fd )
		sock_arr_len = fd+1;
	return fd;
}

int sAccept(int fd, struct sockaddr* addr, int* addrlen)
{
	SOCKET s;

	// accept connection
	s = accept(fd2sock(fd), addr, addrlen);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

int sClose(int fd)
{
	int ret = closesocket(fd2sock(fd));
	fd2sock(fd) = INVALID_SOCKET;
	return ret;
}

int sSocket(int af, int type, int protocol)
{
	SOCKET s;

	// create socket
	s = socket(af,type,protocol);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

char* sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

#define sBind(fd,name,namelen) bind(fd2sock(fd),name,namelen)
#define sConnect(fd,name,namelen) connect(fd2sock(fd),name,namelen)
#define sIoctl(fd,cmd,argp) ioctlsocket(fd2sock(fd),cmd,argp)
#define sListen(fd,backlog) listen(fd2sock(fd),backlog)
#define sRecv(fd,buf,len,flags) recv(fd2sock(fd),buf,len,flags)
#define sSelect select
#define sSend(fd,buf,len,flags) send(fd2sock(fd),buf,len,flags)
#define sSetsockopt(fd,level,optname,optval,optlen) setsockopt(fd2sock(fd),level,optname,optval,optlen)
#define sShutdown(fd,how) shutdown(fd2sock(fd),how)
#define sFD_SET(fd,set) FD_SET(fd2sock(fd),set)
#define sFD_CLR(fd,set) FD_CLR(fd2sock(fd),set)
#define sFD_ISSET(fd,set) FD_ISSET(fd2sock(fd),set)
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#else
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif
/////////////////////////////////////////////////////////////////////

#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
#endif

fd_set readfds;
int fd_max;
time_t last_tick;
time_t stall_time = 60;

uint32 addr_[16];   // ip addresses of local host (host byte order)
int naddr_ = 0;   // # of ip addresses

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
#if PACKETVER < 20131223
static size_t socket_max_client_packet = 0x6000;
#else
static size_t socket_max_client_packet = USHRT_MAX;
#endif

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

struct socket_data* session[FD_SETSIZE];

#ifdef SEND_SHORTLIST
int send_shortlist_array[FD_SETSIZE];// we only support FD_SETSIZE sockets, limit the array to that
int send_shortlist_count = 0;// how many fd's are in the shortlist
uint32 send_shortlist_set[(FD_SETSIZE+31)/32];// to know if specific fd's are already in the shortlist
#endif

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse);

#ifndef MINICORE
	int ip_rules = 1;
	static int connect_check(uint32 ip);
#endif

const char* error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/*======================================
 *	CORE : Default processing functions
 *--------------------------------------*/
int null_recv(int fd) { return 0; }
int null_send(int fd) { return 0; }
int null_parse(int fd) { return 0; }

ParseFunc default_func_parse = null_parse;

void set_defaultparse(ParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}


/*======================================
 *	CORE : Socket options
 *--------------------------------------*/
void set_nonblocking(int fd, unsigned long yes)
{
	// FIONBIO Use with a nonzero argp parameter to enable the nonblocking mode of socket s.
	// The argp parameter is zero if nonblocking is to be disabled.
	if( sIoctl(fd, FIONBIO, &yes) != 0 )
		ShowError("set_nonblocking: Failed to set socket #%d to non-blocking mode (%s) - Please report this!!!\n", fd, error_msg());
}

void setsocketopts(int fd,int delay_timeout){
	int yes = 1; // reuse fix

#if !defined(WIN32)
	// set SO_REAUSEADDR to true, unix only. on windows this option causes
	// the previous owner of the socket to give up, which is not desirable
	// in most cases, neither compatible with unix.
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&yes,sizeof(yes));
#ifdef SO_REUSEPORT
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEPORT,(char *)&yes,sizeof(yes));
#endif
#endif

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	sSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winsock/winsock/closesocket_2.asp)
	{
	struct linger opt;
	opt.l_onoff = 0; // SO_DONTLINGER
	opt.l_linger = 0; // Do not care
	if( sSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&opt, sizeof(opt)) )
		ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection #%d!\n", fd);
	}
	if(delay_timeout){
		struct timeval timeout;
		timeout.tv_sec = delay_timeout;
		timeout.tv_usec = 0;

		if (sSetsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_RCVTIMEO timeout for connection #%d!\n");
		if (sSetsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_SNDTIMEO timeout for connection #%d!\n");
	}
}

/*======================================
 *	CORE : Socket Sub Function
 *--------------------------------------*/
void set_eof(int fd)
{
	if( session_isActive(fd) )
	{
#ifdef SEND_SHORTLIST
		// Add this socket to the shortlist for eof handling.
		send_shortlist_add_fd(fd);
#endif
		session[fd]->flag.eof = 1;
	}
}

int recv_to_fifo(int fd)
{
	int len;

	if( !session_isActive(fd) )
		return -1;

	len = sRecv(fd, (char *) session[fd]->rdata + session[fd]->rdata_size, (int)RFIFOSPACE(fd), 0);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("recv_to_fifo: %s, closing connection #%d\n", error_msg(), fd);
			set_eof(fd);
		}
		return 0;
	}

	if( len == 0 )
	{//Normal connection end.
		set_eof(fd);
		return 0;
	}

	session[fd]->rdata_size += len;
	session[fd]->rdata_tick = last_tick;
#ifdef SHOW_SERVER_STATS
	socket_data_i += len;
	socket_data_qi += len;
	if (!session[fd]->flag.server)
	{
		socket_data_ci += len;
	}
#endif
	return 0;
}

int send_from_fifo(int fd)
{
	int len;

	if( !session_isValid(fd) )
		return -1;

	if( session[fd]->wdata_size == 0 )
		return 0; // nothing to send

	len = sSend(fd, (const char *) session[fd]->wdata, (int)session[fd]->wdata_size, MSG_NOSIGNAL);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("send_from_fifo: %s, ending connection #%d\n", error_msg(), fd);
#ifdef SHOW_SERVER_STATS
			socket_data_qo -= session[fd]->wdata_size;
#endif
			session[fd]->wdata_size = 0; //Clear the send queue as we can't send anymore. [Skotlex]
			set_eof(fd);
		}
		return 0;
	}

	if( len > 0 )
	{
		// some data could not be transferred?
		// shift unsent data to the beginning of the queue
		if( (size_t)len < session[fd]->wdata_size )
			memmove(session[fd]->wdata, session[fd]->wdata + len, session[fd]->wdata_size - len);

		session[fd]->wdata_size -= len;
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if (!session[fd]->flag.server)
		{
			socket_data_co += len;
		}
#endif
	}

	return 0;
}

/// Best effort - there's no warranty that the data will be sent.
void flush_fifo(int fd)
{
	if(session[fd] != NULL)
		session[fd]->func_send(fd);
}

void flush_fifos(void)
{
	int i;
	for(i = 1; i < fd_max; i++)
		flush_fifo(i);
}

/*======================================
 *	CORE : Connection functions
 *--------------------------------------*/
int connect_client(int listen_fd)
{
	int fd;
	struct sockaddr_in client_address;
	socklen_t len;

	len = sizeof(client_address);

	fd = sAccept(listen_fd, (struct sockaddr*)&client_address, &len);
	if ( fd == -1 ) {
		ShowError("connect_client: accept failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("connect_client: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("connect_client: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

#ifndef MINICORE
	if( ip_rules && !connect_check(ntohl(client_address.sin_addr.s_addr)) ) {
		do_close(fd);
		return -1;
	}
#endif

	if( fd_max <= fd ) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);

	return fd;
}

int make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if( fd == -1 )
	{
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		exit(EXIT_FAILURE);
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_listen_bind: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_listen_bind: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	result = sBind(fd, (struct sockaddr*)&server_address, sizeof(server_address));
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: bind failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}
	result = sListen(fd,5);
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: listen failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}

	if(fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd, &readfds);

	create_session(fd, connect_client, null_send, null_parse);
	session[fd]->client_addr = 0; // just listens
	session[fd]->rdata_tick = 0; // disable timeouts on this socket

	return fd;
}

int make_connection(uint32 ip, uint16 port, bool silent,int timeout) {
	struct sockaddr_in remote_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if (fd == -1) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_connection: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_connection: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,timeout);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if( !silent )
		ShowStatus("Connecting to %d.%d.%d.%d:%i\n", CONVIP(ip), port);

	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));
	if( result == SOCKET_ERROR ) {
		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());
		do_close(fd);
		return -1;
	}
	//Now the socket can be made non-blocking. [Skotlex]
	set_nonblocking(fd, 1);

	if (fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(remote_address.sin_addr.s_addr);

	return fd;
}

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse)
{
	CREATE(session[fd], struct socket_data, 1);
	CREATE(session[fd]->rdata, unsigned char, RFIFO_SIZE);
	CREATE(session[fd]->wdata, unsigned char, WFIFO_SIZE);
	session[fd]->max_rdata  = RFIFO_SIZE;
	session[fd]->max_wdata  = WFIFO_SIZE;
	session[fd]->func_recv  = func_recv;
	session[fd]->func_send  = func_send;
	session[fd]->func_parse = func_parse;
	session[fd]->rdata_tick = last_tick;
	return 0;
}

static void delete_session(int fd)
{
	if( session_isValid(fd) )
	{
#ifdef SHOW_SERVER_STATS
		socket_data_qi -= session[fd]->rdata_size - session[fd]->rdata_pos;
		socket_data_qo -= session[fd]->wdata_size;
#endif
		aFree(session[fd]->rdata);
		aFree(session[fd]->wdata);
		aFree(session[fd]->session_data);
		aFree(session[fd]);
		session[fd] = NULL;
	}
}

int realloc_fifo(int fd, unsigned int rfifo_size, unsigned int wfifo_size)
{
	if( !session_isValid(fd) )
		return 0;

	if( session[fd]->max_rdata != rfifo_size && session[fd]->rdata_size < rfifo_size) {
		RECREATE(session[fd]->rdata, unsigned char, rfifo_size);
		session[fd]->max_rdata  = rfifo_size;
	}

	if( session[fd]->max_wdata != wfifo_size && session[fd]->wdata_size < wfifo_size) {
		RECREATE(session[fd]->wdata, unsigned char, wfifo_size);
		session[fd]->max_wdata  = wfifo_size;
	}
	return 0;
}

int realloc_writefifo(int fd, size_t addition)
{
	size_t newsize;

	if( !session_isValid(fd) ) // might not happen
		return 0;

	if( session[fd]->wdata_size + addition  > session[fd]->max_wdata )
	{	// grow rule; grow in multiples of WFIFO_SIZE
		newsize = WFIFO_SIZE;
		while( session[fd]->wdata_size + addition > newsize ) newsize += WFIFO_SIZE;
	}
	else
	if( session[fd]->max_wdata >= (size_t)2*(session[fd]->flag.server?FIFOSIZE_SERVERLINK:WFIFO_SIZE)
		&& (session[fd]->wdata_size+addition)*4 < session[fd]->max_wdata )
	{	// shrink rule, shrink by 2 when only a quarter of the fifo is used, don't shrink below nominal size.
		newsize = session[fd]->max_wdata / 2;
	}
	else // no change
		return 0;

	RECREATE(session[fd]->wdata, unsigned char, newsize);
	session[fd]->max_wdata  = newsize;

	return 0;
}

/// advance the RFIFO cursor (marking 'len' bytes as processed)
int RFIFOSKIP(int fd, size_t len)
{
    struct socket_data *s;

	if ( !session_isActive(fd) )
		return 0;

	s = session[fd];

	if ( s->rdata_size < s->rdata_pos + len ) {
		ShowError("RFIFOSKIP: skipped past end of read buffer! Adjusting from %d to %d (session #%d)\n", len, RFIFOREST(fd), fd);
		len = RFIFOREST(fd);
	}

	s->rdata_pos = s->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif
	return 0;
}

/// advance the WFIFO cursor (marking 'len' bytes for sending)
int WFIFOSET(int fd, size_t len)
{
	size_t newreserve;
	struct socket_data* s = session[fd];

	if( !session_isValid(fd) || s->wdata == NULL )
		return 0;

	// we have written len bytes to the buffer already before calling WFIFOSET
	if(s->wdata_size+len > s->max_wdata)
	{	// actually there was a buffer overflow already
		uint32 ip = s->client_addr;
		ShowFatalError("WFIFOSET: Write Buffer Overflow. Connection %d (%d.%d.%d.%d) has written %u bytes on a %u/%u bytes buffer.\n", fd, CONVIP(ip), (unsigned int)len, (unsigned int)s->wdata_size, (unsigned int)s->max_wdata);
		ShowDebug("Likely command that caused it: 0x%x\n", (*(uint16*)(s->wdata + s->wdata_size)));
		// no other chance, make a better fifo model
		exit(EXIT_FAILURE);
	}

	if( len > 0xFFFF )
	{
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowFatalError("WFIFOSET: Packet 0x%x is too big. (len=%u, max=%u)\n", (*(uint16*)(s->wdata + s->wdata_size)), (unsigned int)len, 0xFFFF);
		exit(EXIT_FAILURE);
	}
	else if( len == 0 )
	{
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET: Attempted to send zero-length packet, most likely 0x%04x (please report this).\n", WFIFOW(fd,0));
		return 0;
	}

	if( !s->flag.server ) {

		if( len > socket_max_client_packet ) {// see declaration of socket_max_client_packet for details
			ShowError("WFIFOSET: Dropped too large client packet 0x%04x (length=%u, max=%u).\n", WFIFOW(fd,0), len, socket_max_client_packet);
			return 0;
		}

		if( s->wdata_size+len > WFIFO_MAX ) {// reached maximum write fifo size
			ShowError("WFIFOSET: Maximum write buffer size for client connection %d exceeded, most likely caused by packet 0x%04x (len=%u, ip=%lu.%lu.%lu.%lu).\n", fd, WFIFOW(fd,0), len, CONVIP(s->client_addr));
			set_eof(fd);
			return 0;
		}

	}

	// Gepard Shield
	if (is_gepard_active == true)
	{
		gepard_process_packet(fd, s->wdata + s->wdata_size, len, &s->send_crypt);
	}
	// Gepard Shield

	s->wdata_size += len;
#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif
	//If the interserver has 200% of its normal size full, flush the data.
	if( s->flag.server && s->wdata_size >= 2*FIFOSIZE_SERVERLINK )
		flush_fifo(fd);

	// always keep a WFIFO_SIZE reserve in the buffer
	// For inter-server connections, let the reserve be 1/4th of the link size.
	newreserve = s->flag.server ? FIFOSIZE_SERVERLINK / 4 : WFIFO_SIZE;

	// readjust the buffer to include the chosen reserve
	realloc_writefifo(fd, newreserve);

#ifdef SEND_SHORTLIST
	send_shortlist_add_fd(fd);
#endif

	return 0;
}

int do_sockets(int next)
{
	fd_set rfd;
	struct timeval timeout;
	int ret,i;

	// PRESEND Timers are executed before do_sendrecv and can send packets and/or set sessions to eof.
	// Send remaining data and process client-side disconnects here.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);
	}
#endif

	// can timeout until the next tick
	timeout.tv_sec  = next/1000;
	timeout.tv_usec = next%1000*1000;

	memcpy(&rfd, &readfds, sizeof(rfd));
	ret = sSelect(fd_max, &rfd, NULL, NULL, &timeout);

	if( ret == SOCKET_ERROR )
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: select() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}

	last_tick = time(NULL);

#if defined(WIN32)
	// on windows, enumerating all members of the fd_set is way faster if we access the internals
	for( i = 0; i < (int)rfd.fd_count; ++i )
	{
		int fd = sock2fd(rfd.fd_array[i]);
		if( session[fd] )
			session[fd]->func_recv(fd);
	}
#else
	// otherwise assume that the fd_set is a bit-array and enumerate it in a standard way
	for( i = 1; ret && i < fd_max; ++i )
	{
		if(sFD_ISSET(i,&rfd) && session[i])
		{
			session[i]->func_recv(i);
			--ret;
		}
	}
#endif

	// POSTSEND Send remaining data and handle eof sessions.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);

		if(session[i]->flag.eof) //func_send can't free a session, this is safe.
		{	//Finally, even if there is no data to parse, connections signalled eof should be closed, so we call parse_func [Skotlex]
			session[i]->func_parse(i); //This should close the session immediately.
		}
	}
#endif

	// parse input data on each socket
	for(i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if (session[i]->rdata_tick && DIFF_TICK(last_tick, session[i]->rdata_tick) > stall_time) {
			if( session[i]->flag.server ) {/* server is special */
				if( session[i]->flag.ping != 2 )/* only update if necessary otherwise it'd resend the ping unnecessarily */
					session[i]->flag.ping = 1;
			} else {
				ShowInfo("Session #%d timed out\n", i);
				set_eof(i);
			}
		}

		session[i]->func_parse(i);

		if(!session[i])
			continue;

		// after parse, check client's RFIFO size to know if there is an invalid packet (too big and not parsed)
		if (session[i]->rdata_size == RFIFO_SIZE && session[i]->max_rdata == RFIFO_SIZE) {
			set_eof(i);
			continue;
		}
		RFIFOFLUSH(i);
	}

#ifdef SHOW_SERVER_STATS
	if (last_tick != socket_data_last_tick)
	{
		char buf[1024];
		
		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., malloc_usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif
		socket_data_last_tick = last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif

	return 0;
}

//////////////////////////////
#ifndef MINICORE
//////////////////////////////
// IP rules and DDoS protection

typedef struct _connect_history {
	struct _connect_history* next;
	uint32 ip;
	uint32 tick;
	int count;
	unsigned ddos : 1;
} ConnectHistory;

typedef struct _access_control {
	uint32 ip;
	uint32 mask;
} AccessControl;

enum _aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static AccessControl* access_allow = NULL;
static AccessControl* access_deny = NULL;
static int access_order    = ACO_DENY_ALLOW;
static int access_allownum = 0;
static int access_denynum  = 0;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
/// Connection history, an array of linked lists.
/// The array's index for any ip is ip&0xFFFF
static ConnectHistory* connect_history[0x10000];

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %d.%d.%d.%d %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	ConnectHistory* hist = connect_history[ip&0xFFFF];
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for( i=0; i < access_allownum; ++i ){
		if( (ip & access_allow[i].mask) == (access_allow[i].ip & access_allow[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from allow list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_allow[i].ip),
					CONVIP(access_allow[i].mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for( i=0; i < access_denynum; ++i ){
		if( (ip & access_deny[i].mask) == (access_deny[i].ip & access_deny[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from deny list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_deny[i].ip),
					CONVIP(access_deny[i].mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
	case ACO_DENY_ALLOW:
	default:
		if( is_denyip )
			connect_ok = 0; // Reject
		else if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 1; // Accept
		break;
	case ACO_ALLOW_DENY:
		if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else if( is_denyip )
			connect_ok = 0; // Reject
		else
			connect_ok = 1; // Accept
		break;
	case ACO_MUTUAL_FAILURE:
		if( is_allowip && !is_denyip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 0; // Reject
		break;
	}

	// Inspect connection history
	while( hist ) {
		if( ip == hist->ip )
		{// IP found
			if( hist->ddos )
			{// flagged as DDoS
				return (connect_ok == 2 ? 1 : 0);
			} else if( DIFF_TICK(gettick(),hist->tick) < ddos_interval )
			{// connection within ddos_interval
				hist->tick = gettick();
				if( hist->count++ >= ddos_count )
				{// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %d.%d.%d.%d!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
			} else
			{// not within ddos_interval, clear data
				hist->tick  = gettick();
				hist->count = 0;
				return connect_ok;
			}
		}
		hist = hist->next;
	}
	// IP not found, add to history
	CREATE(hist, ConnectHistory, 1);
	memset(hist, 0, sizeof(ConnectHistory));
	hist->ip   = ip;
	hist->tick = gettick();
	hist->next = connect_history[ip&0xFFFF];
	connect_history[ip&0xFFFF] = hist;
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static int connect_check_clear(int tid, unsigned int tick, int id, intptr_t data)
{
	int i;
	int clear = 0;
	int list  = 0;
	ConnectHistory root;
	ConnectHistory* prev_hist;
	ConnectHistory* hist;

	for( i=0; i < 0x10000 ; ++i ){
		prev_hist = &root;
		root.next = hist = connect_history[i];
		while( hist ){
			if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
					(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				prev_hist->next = hist->next;
				aFree(hist);
				hist = prev_hist->next;
				clear++;
			} else {
				prev_hist = hist;
				hist = hist->next;
			}
			list++;
		}
		connect_history[i] = root.next;
	}
	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}
	return list;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
int access_ipmask(const char* str, AccessControl* acc)
{
	uint32 ip;
	uint32 mask;

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%3u.%3u.%3u.%3u/%3u.%3u.%3u.%3u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u/%3u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%d.%d.%d.%d mask:%d.%d.%d.%d\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}
//////////////////////////////
#endif
//////////////////////////////

int socket_config_read(const char* cfgName)
{
	char line[1024],w1[1024],w2[1024];
	FILE *fp;

	fp = fopen(cfgName, "r");
	if(fp == NULL) {
		ShowError("File not found: %s\n", cfgName);
		return 1;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if(line[0] == '/' && line[1] == '/')
			continue;
		if(sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		if (!strcmpi(w1, "stall_time")) {
			stall_time = atoi(w2);
			if( stall_time < 3 )
				stall_time = 3;/* a minimum is required to refrain it from killing itself */
		}
#ifndef MINICORE
		else if (!strcmpi(w1, "enable_ip_rules")) {
			ip_rules = config_switch(w2);
		} else if (!strcmpi(w1, "order")) {
			if (!strcmpi(w2, "deny,allow"))
				access_order = ACO_DENY_ALLOW;
			else if (!strcmpi(w2, "allow,deny"))
				access_order = ACO_ALLOW_DENY;
			else if (!strcmpi(w2, "mutual-failure"))
				access_order = ACO_MUTUAL_FAILURE;
		} else if (!strcmpi(w1, "allow")) {
			RECREATE(access_allow, AccessControl, access_allownum+1);
			if (access_ipmask(w2, &access_allow[access_allownum]))
				++access_allownum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		} else if (!strcmpi(w1, "deny")) {
			RECREATE(access_deny, AccessControl, access_denynum+1);
			if (access_ipmask(w2, &access_deny[access_denynum]))
				++access_denynum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		}
		else if (!strcmpi(w1,"ddos_interval"))
			ddos_interval = atoi(w2);
		else if (!strcmpi(w1,"ddos_count"))
			ddos_count = atoi(w2);
		else if (!strcmpi(w1,"ddos_autoreset"))
			ddos_autoreset = atoi(w2);
		else if (!strcmpi(w1,"debug"))
			access_debug = config_switch(w2);
#endif
		else if (!strcmpi(w1, "import"))
			socket_config_read(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}


void socket_final(void)
{
	int i;
#ifndef MINICORE
	ConnectHistory* hist;
	ConnectHistory* next_hist;

	for( i=0; i < 0x10000; ++i ){
		hist = connect_history[i];
		while( hist ){
			next_hist = hist->next;
			aFree(hist);
			hist = next_hist;
		}
	}
	if( access_allow )
		aFree(access_allow);
	if( access_deny )
		aFree(access_deny);
#endif

	for( i = 1; i < fd_max; i++ )
		if(session[i])
			do_close(i);

	// session[0]
	aFree(session[0]->rdata);
	aFree(session[0]->wdata);
	aFree(session[0]->session_data);
	aFree(session[0]);
	session[0] = NULL;
}

/// Closes a socket.
void do_close(int fd)
{
	if( fd <= 0 ||fd >= FD_SETSIZE )
		return;// invalid

	flush_fifo(fd); // Try to send what's left (although it might not succeed since it's a nonblocking socket)
	sFD_CLR(fd, &readfds);// this needs to be done before closing the socket
	sShutdown(fd, SHUT_RDWR); // Disallow further reads/writes
	sClose(fd); // We don't really care if these closing functions return an error, we are just shutting down and not reusing this socket.
	if (session[fd]) delete_session(fd);
}

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
int socket_getips(uint32* ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];	

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if( gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR )
		{
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		}
		else
		{
			u_long** a;
			struct hostent* hent;
			hent = gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for( ;num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if( sIoctl(fd, SIOCGIFCONF, &ic) == -1 )
		{
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			return 0;
		}
		else
		{
			int pos;
			for( pos=0; pos < ic.ifc_len && num < max; )
			{
				struct ifreq* ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in*a = (struct sockaddr_in*) &(ir->ifr_addr);
				if( a->sin_family == AF_INET ){
					ad = ntohl(a->sin_addr.s_addr);
					if( ad != INADDR_LOOPBACK && ad != INADDR_ANY )
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

void socket_init(void)
{
	char *SOCKET_CONF_FILENAME = "conf/packet_athena.conf";
	unsigned int rlim_cur = FD_SETSIZE;

#ifdef WIN32
	{// Start up windows networking
		WSADATA wsaData;
		WORD wVersionRequested = MAKEWORD(2, 0);
		if( WSAStartup(wVersionRequested, &wsaData) != 0 )
		{
			ShowError("socket_init: WinSock not available!\n");
			return;
		}
		if( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0 )
		{
			ShowError("socket_init: WinSock version mismatch (2.0 or compatible required)!\n");
			return;
		}
	}
#elif defined(HAVE_SETRLIMIT) && !defined(CYGWIN)
	// NOTE: getrlimit and setrlimit have bogus behaviour in cygwin.
	//       "Number of fds is virtually unlimited in cygwin" (sys/param.h)
	{// set socket limit to FD_SETSIZE
		struct rlimit rlp;
		if( 0 == getrlimit(RLIMIT_NOFILE, &rlp) )
		{
			rlp.rlim_cur = FD_SETSIZE;
			if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
			{// failed, try setting the maximum too (permission to change system limits is required)
				rlp.rlim_max = FD_SETSIZE;
				if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
				{// failed
					const char *errmsg = error_msg();
					int rlim_ori;
					// set to maximum allowed
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_ori = (int)rlp.rlim_cur;
					rlp.rlim_cur = rlp.rlim_max;
					setrlimit(RLIMIT_NOFILE, &rlp);
					// report limit
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_cur = rlp.rlim_cur;
					ShowWarning("socket_init: failed to set socket limit to %d, setting to maximum allowed (original limit=%d, current limit=%d, maximum allowed=%d, %s).\n", FD_SETSIZE, rlim_ori, (int)rlp.rlim_cur, (int)rlp.rlim_max, errmsg);
				}
			}
		}
	}
#endif

	// Get initial local ips
	naddr_ = socket_getips(addr_,16);

	sFD_ZERO(&readfds);
#if defined(SEND_SHORTLIST)
	memset(send_shortlist_set, 0, sizeof(send_shortlist_set));
#endif

	socket_config_read(SOCKET_CONF_FILENAME);

	// Gepard Shield
	gepard_config_read();
	// Gepard Shield

	// initialise last send-receive tick
	last_tick = time(NULL);

	// session[0] is now currently used for disconnected sessions of the map server, and as such,
	// should hold enough buffer (it is a vacuum so to speak) as it is never flushed. [Skotlex]
	create_session(0, null_recv, null_send, null_parse); //FIXME this is causing leak

#ifndef MINICORE
	// Delete old connection history every 5 minutes
	memset(connect_history, 0, sizeof(connect_history));
	add_timer_func_list(connect_check_clear, "connect_check_clear");
	add_timer_interval(gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);
#endif

	ShowInfo("Server supports up to '"CL_WHITE"%u"CL_RESET"' concurrent connections.\n", rlim_cur);
}


bool session_isValid(int fd)
{
	return ( fd > 0 && fd < FD_SETSIZE && session[fd] != NULL );
}

bool session_isActive(int fd)
{
	return ( session_isValid(fd) && !session[fd]->flag.eof );
}

// Resolves hostname into a numeric ip.
uint32 host2ip(const char* hostname)
{
	struct hostent* h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

// Converts a numeric ip into a dot-formatted string.
// Result is placed either into a user-provided buffer or a static system buffer.
const char* ip2str(uint32 ip, char ip_str[16])
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
uint32 str2ip(const char* ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Neccessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending or eof handling.
void send_shortlist_add_fd(int fd)
{
	int i;
	int bit;

	if( !session_isValid(fd) )
		return;// out of range

	i = fd/32;
	bit = fd%32;

	if( (send_shortlist_set[i]>>bit)&1 )
		return;// already in the list

	if( send_shortlist_count >= ARRAYLENGTH(send_shortlist_array) )
	{
		ShowDebug("send_shortlist_add_fd: shortlist is full, ignoring... (fd=%d shortlist.count=%d shortlist.length=%d)\n", fd, send_shortlist_count, ARRAYLENGTH(send_shortlist_array));
		return;
	}

	// set the bit
	send_shortlist_set[i] |= 1<<bit;
	// Add to the end of the shortlist array.
	send_shortlist_array[send_shortlist_count++] = fd;
}

// Do pending network sends and eof handling from the shortlist.
void send_shortlist_do_sends()
{
	int i;

	for( i = send_shortlist_count-1; i >= 0; --i )
	{
		int fd = send_shortlist_array[i];
		int idx = fd/32;
		int bit = fd%32;

		// Remove fd from shortlist, move the last fd to the current position
		--send_shortlist_count;
		send_shortlist_array[i] = send_shortlist_array[send_shortlist_count];
		send_shortlist_array[send_shortlist_count] = 0;

		if( fd <= 0 || fd >= FD_SETSIZE )
		{
			ShowDebug("send_shortlist_do_sends: fd is out of range, corrupted memory? (fd=%d)\n", fd);
			continue;
		}
		if( ((send_shortlist_set[idx]>>bit)&1) == 0 )
		{
			ShowDebug("send_shortlist_do_sends: fd is not set, why is it in the shortlist? (fd=%d)\n", fd);
			continue;
		}
		send_shortlist_set[idx]&=~(1<<bit);// unset fd
		// If this session still exists, perform send operations on it and
		// check for the eof state.
		if( session[fd] )
		{
			// Send data
			if( session[fd]->wdata_size )
				session[fd]->func_send(fd);

			// If it's been marked as eof, call the parse func on it so that
			// the socket will be immediately closed.
			if( session[fd]->flag.eof )
				session[fd]->func_parse(fd);

			// If the session still exists, is not eof and has things left to
			// be sent from it we'll re-add it to the shortlist.
			if( session[fd] && !session[fd]->flag.eof && session[fd]->wdata_size )
				send_shortlist_add_fd(fd);
		}
	}
}
#endif

bool is_gepard_active;
uint32 gepard_rand_seed;
uint32 allowed_gepard_grf_hash;
uint32 min_allowed_gepard_version;

const unsigned char* shield_matrix = (const unsigned char*)

	"\xc8\xd9\x50\x17\x8e\xac\x3c\x22\x94\xf5\xed\x0b\xc9\x21\x25\x5c"
	"\x88\x7f\x23\x76\x06\x2f\x80\xdb\x76\x10\xf1\x49\xe8\x79\x23\x65"
	"\xb3\xc7\xa4\x43\x02\x7a\xa4\x90\x63\x6a\xde\x13\xd7\xd4\xfd\xda"
	"\x4f\x53\x56\x51\x0d\xe5\x44\xfe\xd9\xb3\x0a\x3f\x14\x2e\xee\xa4"
	"\x6d\xa4\x14\x5e\x6e\x8e\xab\xd8\x10\x86\x89\xd6\x82\xca\xc7\xde"
	"\xf7\xb0\x66\xa5\xfb\xe6\xa6\xcb\xb9\x74\x8c\x28\xbd\x4d\x44\x70"
	"\x83\x6c\xd1\xeb\xe8\x47\x50\x97\x61\x1a\x22\x54\x68\x47\x55\x14"
	"\x9e\x5c\xa8\x12\x18\xfc\x68\x1a\xae\x2b\x11\xe0\x78\xc4\x76\x6d"
	"\xa4\x2a\xd6\x23\xea\x5a\x98\xdf\xc0\x07\x22\xc3\x8b\x62\x7b\x18"
	"\x09\xad\x37\xe7\x0f\x46\x51\x35\xf4\xc3\x73\xf7\x36\xd7\x5e\xb5"
	"\xa8\x80\x5e\xef\xd1\xcd\x0d\x36\x3c\xc3\x46\x8a\xd2\x0a\x13\xfe"
	"\x9b\x8d\x70\xab\x6e\xb3\x2b\xdd\x6b\x3f\xd2\xad\x51\x1d\xd6\x55"
	"\x85\x24\xe8\x72\xde\x7e\xb9\x16\x07\x59\x90\x46\x88\xfe\x7c\xcf"
	"\x63\xfd\x75\x98\x2b\x8b\x46\xc8\x16\xaf\x91\xfa\x84\xfe\xbf\x4d"
	"\xda\x5d\x3b\xfc\xb7\x1c\x2f\xed\x74\x67\xc6\xc7\xda\xd5\x97\x05"
	"\x0d\x12\x2e\x9a\x9b\xe7\xf2\x9c\x1e\xbf\x57\x89\x72\x3d\x7d\x14"
	"\xe6\x0c\xdc\x17\x67\xaa\x82\x1d\x22\x21\xef\x92\x5c\x77\x49\x0e"
	"\xed\xee\x43\xd3\xfa\xb5\x0b\xf5\xcd\xab\x8f\x38\x1e\x69\x76\x11"
	"\x11\x1f\x1a\xfc\xd7\x01\x4c\x7c\xc8\xca\xd9\xe0\x04\xa0\x7c\x4e"
	"\xfb\x51\x24\x99\xe9\xb7\xe5\xe5\x96\x41\xe8\x98\x70\xea\x97\x21"
	"\x61\x9c\x82\x1e\xdc\x4b\x28\x55\x8d\x3e\x97\x9d\x2b\x61\x1f\x1c"
	"\x51\x88\x82\x76\xea\x03\xe3\xee\x8a\x67\x56\xf1\xb4\x7b\x4f\x16"
	"\x04\x9e\x6b\x9d\x2c\x89\xb8\x64\x37\xeb\x7b\xe9\x91\x1f\xa1\x42"
	"\xad\xf7\xd3\xa6\x65\x80\xe7\x09\x63\x95\x8f\x3f\x9c\x2c\x12\xb5"
	"\x4a\x51\xeb\xd2\x5d\x0f\x22\x5d\xce\xd4\xa1\x1b\xd7\x92\x79\x22"
	"\x73\x96\x53\x9c\x25\x70\x57\x22\xfb\x57\x90\x2d\xbb\xdd\xd7\x37"
	"\x29\xf5\xe0\x4a\x6f\x05\x8b\x66\x01\x90\xe3\x38\x06\xc8\xa1\x09"
	"\xa9\x6f\xfd\x7d\x59\xe2\x1e\x98\xd3\x4d\x96\x20\x0b\xc7\x1b\xc9"
	"\xb9\x62\xea\x43\x42\xe4\x23\x17\x20\x47\x66\x7e\x05\xa1\x18\x04"
	"\x7b\xa1\x17\xa2\x95\x3d\xaa\x40\x90\xac\x26\x2f\x66\x75\x5b\x0d"
	"\xb8\x80\x6c\x30\x1d\x80\x98\x22\xa3\xb7\x8c\x5f\x25\x53\xdd\x0d"
	"\xb7\x61\x23\x99\xd1\xba\xee\x61\xf8\x3d\x85\xa2\x8e\xc4\x9d\x16"
	"\x07\x4c\x0f\xb9\xa8\xfa\xa0\xa1\xa3\x36\x22\xfd\x97\x65\x77\x31"
	"\x51\x75\x6e\x24\x67\x67\xe1\x39\xf8\xd9\xc0\x7a\xa8\x69\x69\x6d"
	"\x29\xd6\x3e\x3a\xf1\x4b\x75\x73\xde\xa7\xad\x33\xf2\x35\x6f\xf3"
	"\xde\xb9\x85\x38\x97\x27\xfd\xf6\x20\x75\xa5\x68\xbb\xe8\xc9\x91"
	"\xc9\x47\xaa\xc3\xe9\xbe\xd1\xdd\x37\x85\xc7\x0c\x31\x73\xd3\xcc"
	"\x1c\x9b\xbb\xfd\x85\xad\x43\x3f\x23\x12\x49\xd3\x34\x1e\x4e\x72"
	"\x33\xd4\xc7\x96\x67\x74\xf6\xc0\xb2\xde\x42\xc8\x31\x24\x36\x27"
	"\xe6\x21\xa6\xd4\xb7\x06\x32\xa8\xd8\xc8\x02\xd6\x64\x39\x0c\x75"
	"\x57\x4f\xce\x2c\x22\xde\x2a\xeb\x7b\x56\xd6\x5d\x35\xa1\x2b\x61"
	"\x42\x5f\x20\xcc\x9b\x0e\x53\x40\x3f\xc6\xe9\x3f\xfd\x3c\x97\xf3"
	"\xcc\x15\x3a\xaf\xb8\x48\xb3\xa7\x5e\x22\x82\xf2\xe3\x97\xcd\xce"
	"\x56\x82\x47\xab\x7d\xf6\xaf\x05\xf3\xc9\x60\x91\x1c\xfd\x8f\x3a"
	"\xca\x1c\x4c\x81\xac\x4a\xdf\x2c\x4d\x0b\x06\x66\x47\x07\xba\xb6"
	"\x6d\xc8\x7c\xeb\x93\x46\x57\xec\x3b\xa9\x0a\x82\x39\x28\x92\x89"
	"\x2d\x6f\x08\xb2\x62\xd5\x22\x28\x60\x71\xe7\xc7\xcd\xc4\x94\x53"
	"\xf4\x87\xe7\x3a\x74\x57\xdc\xde\x7e\x4b\xcd\xfc\xb5\x3c\x44\x97"
	"\x77\xaa\x35\x8d\xa3\xad\x67\xbe\x4e\x47\xef\xda\x4a\xf9\x7f\x54"
	"\x81\x24\x72\xf7\x1a\xd5\x56\x36\xc7\x2d\x56\x20\xd7\x0a\xcb\x8c"
	"\xcc\x80\xe0\x8c\x1e\x6b\x70\x04\x77\x91\x2b\x1a\x73\xa2\xa6\xdb"
	"\xc9\x9b\xca\xbb\xe5\x44\x5d\x44\xc8\xde\x11\x3d\x46\xb9\xd5\x06"
	"\xf5\x34\x5a\x5f\x64\xf8\x76\x03\x5c\xea\x6c\x30\x62\x8f\xb7\x82"
	"\xa8\x7b\x63\xcd\x1a\x78\x13\x4c\x53\x05\x34\xdc\x0e\x45\x11\x15"
	"\xe0\x21\xb6\x68\xe8\x17\xda\x3a\x24\x82\x46\x7f\x16\x67\xe2\x53"
	"\x9b\xe6\x71\x2c\xde\x9d\x97\x86\xe1\x56\xb4\xb7\x1f\x7d\x32\x3d"
	"\x1e\x32\xcc\x40\x88\x59\x03\x1b\x96\x1a\x94\x99\xf1\x20\x5e\xca"
	"\x47\x97\xef\x87\x3f\x2f\x14\x9f\x8e\xa0\x4e\x3d\x4e\x82\x6f\xf9"
	"\x62\xeb\x3a\x32\x7d\xa7\xd5\x0b\x24\x88\xf1\x4a\xbb\x87\x65\xde"
	"\x72\x56\x1c\xc7\x2a\x01\xb1\x36\x99\x45\x02\x0f\x54\x4d\x06\x36"
	"\x07\x60\xde\x3e\x6b\x3e\x40\xe5\xdd\x37\x42\x8b\x9c\xbf\xb2\x74"
	"\x88\x04\xf8\x04\x73\xb7\x1e\x5f\xe5\x35\x0f\x84\xcc\x27\xb4\xd4"
	"\x08\xba\x5e\x17\xd6\x2b\xb4\xf6\xf8\xa3\xa8\x90\xa4\xbb\x8b\xe7"
	"\x16\x13\x4c\x0c\xd3\x4d\x0e\x22\x7d\xfb\x22\xa8\x39\x30\x3f\x29"
	"\x08\xb7\x20\x24\xa8\x54\x25\x04\xcf\x62\x0e\x3b\x46\x45\xb2\x08"
	"\xcf\x0b\xa0\x5e\xe3\x8e\x37\xfb\x0b\x34\x9e\xb8\xfc\x5a\xed\xfc"
	"\xc9\x29\x52\x02\x2f\xef\x8d\x3f\x60\x98\x21\x25\xd5\xf8\x72\x97"
	"\x0c\x06\x44\x33\xa4\x9f\x54\x5c\x5e\x0e\xfa\xa8\xdf\xeb\x0b\x0e"
	"\x37\xf3\xe2\x22\x1c\x0a\xe7\xd4\xcb\x22\xd2\x1c\x10\xc7\x98\x4e"
	"\xc6\xb5\x48\x73\x7a\xf3\x23\x27\xeb\xce\x67\x9c\x11\x81\x67\x0c"
	"\xdc\x90\x88\xa1\x04\x83\x35\x62\x59\x67\x57\x9e\x12\x76\xf7\xd4"
	"\x9c\x5b\x83\x3b\xaa\x56\xe8\xb4\x4c\xcd\xf9\xf1\x9d\x87\xd5\x9d"
	"\x6d\x0d\x38\x9d\xdf\x8f\xfa\x79\x71\x31\xa8\x61\x5f\x1d\x64\x4d"
	"\x52\xce\x10\xdd\xe2\xe4\xe8\x50\xb9\xf7\x10\x36\x7c\x41\xae\x59"
	"\xba\x8a\x31\xdf\x8e\xb4\xc1\x21\x24\x54\x03\xcd\xdc\xa9\x39\xc9"
	"\x4f\xfb\xcc\xe0\xaf\x11\xf0\xb9\x14\xcd\x48\xaa\x83\x47\x4e\x4e"
	"\xc0\x3f\xf1\x08\x50\x50\x95\xd2\x21\xd8\x68\x80\x57\xdb\x52\xcf"
	"\x1d\xe1\x5a\x7b\x87\x9f\xcd\xa6\x61\xe1\x84\x47\x72\x83\x92\xfc"
	"\x9a\x73\x3f\xe9\x4a\x91\x86\xfc\xbe\xde\x1e\xc9\xf9\xc8\x92\xdb"
	"\x6a\x13\x20\x1e\xbf\x2c\xd1\x3e\x47\x5f\xec\xb6\x67\xb3\xdf\xda"
	"\x88\x83\x20\x0d\x08\xfc\x2c\x80\x78\x19\xac\xae\x59\xd8\x5f\xdd"
	"\x8b\x38\xc8\xe7\x14\x24\xd4\x9b\x12\x7f\x6c\xd5\xe6\x6b\x1e\xcf"
	"\x71\x62\x61\xac\x74\x68\x9c\x34\xe9\xcc\xe0\x65\xea\xc9\x22\xb5"
	"\x76\x8a\xc0\xb0\xa4\x48\x31\x50\x33\x93\xb2\xb8\x59\x91\x39\xb9"
	"\x5d\x95\x94\xb7\x61\x82\xf3\xe2\xd6\x53\x4d\xdc\x8a\xab\x49\x3d"
	"\x45\x5b\x3a\x80\xf4\xad\x45\x5f\xbd\x01\xb1\x25\x0c\xe0\xa0\xe9"
	"\xf8\x34\x8b\xd2\x06\x48\xd4\xc8\xa3\x1d\x45\x36\x74\x63\xc5\xbe"
	"\xb8\x0d\x2d\x94\x6b\xc0\xf3\x41\x68\x40\xa1\x17\xae\xe6\xc6\xa4"
	"\x15\xed\xe0\x55\x79\x0f\x62\x19\xdb\xaa\x64\xc2\x4d\x2a\x8c\x79"
	"\xb2\x16\xd2\xdf\xd3\x3d\xa3\x62\x90\x5b\xfd\x3a\x56\x08\xa5\x23"
	"\xa6\x03\x6e\xc9\x3b\x7e\xc7\x79\x2c\x94\x05\x0e\x99\x8c\x99\x9f"
	"\x3a\x83\xa8\x06\xdd\xb6\x3f\xa1\x36\xf3\x84\x74\x7b\xfb\x37\x12"
	"\xc6\x48\xd4\xf0\xab\x11\xad\x05\x67\x82\xca\x54\x45\xea\x67\x58"
	"\x7a\x73\xf1\xe1\x9c\x90\x35\xd3\xfb\xbe\xb9\x59\xf8\xca\xfa\x93"
	"\xb2\x27\x79\x3e\x0f\x19\xc7\xc8\x82\xb2\x19\x83\x9d\xf9\x7a\xbe"
	"\xc2\x19\xb3\x02\x09\x85\x78\x40\xaa\x83\x63\x35\x90\x54\x76\xbb"
	"\xca\x1e\x04\xd7\x90\xb7\xc9\x46\x18\xf9\x19\x43\xd4\x43\x57\x63"
	"\x84\xbc\x39\xa5\x7b\xa4\x7f\x24\x2e\x9d\x0e\x86\xe5\x4c\x2e\x94"
	"\x93\x3d\xdf\x9a\x3d\x66\x6d\xf4\x65\xbd\x39\xe9\x82\x23\x86\x47"
	"\x57\x38\x90\xc3\x35\x4e\x45\xae\x16\x22\x08\x7e\x82\x38\xb1\x99"
	"\xb7\x29\x3e\x95\x06\x70\x6c\x3c\xcc\x76\x2a\x06\xa0\x4a\x97\xe1"
	"\xf5\x7c\x0b\x84\x5a\xb8\xc7\x05\x96\xab\xe4\x05\x51\x74\x8c\xbc"
	"\x02\x9d\x12\x0d\x40\xf5\x8a\x7d\xd3\xb3\xe0\x56\x0d\x3e\x9b\x1f"
	"\xc0\x0b\x3e\x47\x70\x6d\x0a\xbc\x07\x3b\xfb\x34\xa3\xad\x56\xe3"
	"\x64\x65\x15\x77\x26\x69\x0b\x09\xa4\x18\x96\xcf\x0b\x56\xa7\x5d"
	"\xb8\x7c\x87\x1c\xe4\x4a\x13\x65\xe3\x5a\xe7\x5a\xae\x68\x24\xe5"
	"\xf3\xe2\x42\x80\xd3\x14\x36\x25\x8d\xd9\xc7\x1b\x40\xbf\xd5\x6f"
	"\x06\x7b\x80\x49\x05\x02\x6c\xfb\xcc\x48\x07\xfa\x89\x79\x91\x91"
	"\xe8\x0c\xd9\x87\xcb\x90\xda\x8b\x80\x42\xb6\x15\x37\x7c\x43\x1d"
	"\x72\x48\x8f\xc8\x06\x18\x26\xf5\x86\x5b\xfd\x4b\x30\x8e\x3f\x28"
	"\x21\xe8\xdf\xa1\xf2\x50\x46\x6a\x92\x30\xe8\x4e\x5f\x60\x92\xa0"
	"\xed\x35\xd7\xc6\x7e\x68\xd2\xba\x77\x79\x34\xb5\x84\x24\x51\xdc"
	"\x1d\x96\x9c\x94\x92\x95\x50\x64\x7d\x17\xa5\x8b\x89\x15\x68\xa9"
	"\x0b\x29\xc4\xa5\xe9\xa1\x87\x26\xad\xa0\x53\x5a\xca\x8d\x6e\x5a"
	"\x80\x47\x9d\x5c\xd9\x79\xce\x8e\xa0\x7b\xfa\x43\x6c\x15\x6f\x5b"
	"\x80\x9f\x84\x7a\xa6\xc1\xdf\x89\xd5\xe0\xcb\x8a\x2a\xf1\xc2\xbc"
	"\x16\x40\xb0\x29\xd6\x65\x21\x73\x7c\x77\x3b\x24\xa3\x34\xd4\xcb"
	"\xa8\xa8\x08\x8f\x7a\x22\xfa\xa7\x47\x5e\x50\xcc\x30\xcb\xfc\x96"
	"\xc9\x5a\xeb\x5e\x81\x9b\xa6\x11\x38\x3b\xf8\x0f\x2c\x15\x4a\x86"
	"\x04\xe7\x88\xe1\x8a\x6b\xfa\x39\xf6\x50\xd7\x5b\xcc\xe9\x52\xea"
	"\xac\x83\xa6\x93\x33\xae\xc2\x59\x9c\x87\x90\x96\xe9\x31\x05\x0a"
	"\x34\x12\x7c\xa3\xe3\x1a\x86\xe9\x03\x84\x1d\x26\xd3\x6f\x78\xb3"
	"\xf3\x3b\xfc\x12\x27\x07\xdf\x32\x98\x34\x1c\x84\x21\xd5\xbe\xca"
	"\x80\xf5\x24\xb9\xf4\x02\xc8\x59\xaa\x5b\x9f\xce\xfe\xd2\x2d\x5d"
	"\xf7\x1a\x4e\xdc\x02\x60\xea\x75\xbb\xa9\x7f\xd5\x7e\x22\x36\xae"
	"\x53\x70\x81\x3d\x12\xc7\x70\x1d\x51\xc7\xa3\xac\x69\x5e\x2f\xc9"
	"\x36\xc5\x40\xa4\xc6\xc8\xd2\x72\x3f\xe5\xdd\x39\x8e\x0d\x2b\x91"
	"\xbd\x75\xda\xfb\xf0\x65\x2f\x3b\x7f\xd1\x2f\xc7\x14\x32\x42\xcd";

void gepard_config_read()
{
	char* conf_name = "conf/gepard_shield.conf";
	char line[1024], w1[1024], w2[1024];

	FILE* fp = fopen(conf_name, "r");

	is_gepard_active = false;

	if (fp == NULL) 
	{
		ShowError("Gepard configuration file (%s) not found. Shield disabled.\n", conf_name);
		return;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if (!strcmpi(w1, "gepard_shield_enabled"))
		{
			is_gepard_active = (bool)config_switch(w2);
		}
	}

	fclose(fp);

	conf_name = "conf/gepard_version.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		min_allowed_gepard_version = 0;
		ShowError("Gepard version file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &min_allowed_gepard_version);

	fclose(fp);

	conf_name = "conf/gepard_grf_hash.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		allowed_gepard_grf_hash = 0;
		ShowError("Gepard GRF hash file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &allowed_gepard_grf_hash);

	fclose(fp);
}

bool gepard_process_packet(int fd, uint8* packet_data, uint32 packet_size, struct gepard_crypt_link* link)
{
	uint16 packet_id = RBUFW(packet_data, 0);

	switch (packet_id)
	{
		case CS_GEPARD_SYNC:
		{
			uint32 control_value;

			if (RFIFOREST(fd) < 6)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, 4, &session[fd]->sync_crypt);

			control_value = RFIFOL(fd, 2);

			if (control_value == 0xDDCCBBAA)
			{
				session[fd]->gepard_info.sync_tick = gettick();
			}

			RFIFOSKIP(fd, 6);

			return true;
		}
		break;

		case CS_LOGIN_PACKET_1:
		case CS_LOGIN_PACKET_2:
		case CS_LOGIN_PACKET_3:
		case CS_LOGIN_PACKET_4:
		case CS_LOGIN_PACKET_5:
		case CS_LOGIN_PACKET_6:
		{
			set_eof(fd);
			return true;
		}
		break;

		case CS_LOGIN_PACKET:
		{
			if (RFIFOREST(fd) < 55)
			{
				return false;
			}

			if (session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);	
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, RFIFOREST(fd) - 2, link);
		}
		break;

		case CS_WHISPER_TO:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_WALK_TO_XY:
		case CS_USE_SKILL_TO_ID:
		case CS_USE_SKILL_TO_POS:
		{
			if (packet_size < 2 || RFIFOREST(fd) < packet_size)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, packet_size - 2, link);
		}
		break;

		case SC_WHISPER_FROM:
		case SC_SET_UNIT_IDLE:
		case SC_SET_UNIT_WALKING:
		{
			if (&session[fd]->send_crypt != link)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_GEPARD_INIT_ACK:
		{
			uint32 grf_hash_number;
			uint32 unique_id, unique_id_, shield_ver;

			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RFIFOW(fd, 2)))
			{
				return true;
			}

			if (packet_size < 24)
			{
				ShowWarning("gepard_process_packet: invalid size of CS_GEPARD_INIT_ACK packet: %u\n", packet_size);
				set_eof(fd);
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);

			unique_id  = RFIFOL(fd, 4);
			shield_ver = RFIFOL(fd, 8);
			unique_id_ = RFIFOL(fd, 12) ^ UNIQUE_ID_XOR;
			grf_hash_number = RFIFOL(fd, 20);

			RFIFOSKIP(fd, packet_size);

			if (!unique_id || !unique_id_ || unique_id != unique_id_)
			{
				WFIFOHEAD(fd, 6);
				WFIFOW(fd, 0) = SC_GEPARD_INFO;
				WFIFOL(fd, 2) = 3;
				WFIFOSET(fd, 6);
				set_eof(fd);
			}

			session[fd]->gepard_info.is_init_ack_received = true;
			session[fd]->gepard_info.unique_id = unique_id;
			session[fd]->gepard_info.gepard_shield_version = shield_ver;
			session[fd]->gepard_info.grf_hash_number = grf_hash_number;

			return true;
		}
		break;
	}

	return false;
}

inline void gepard_srand(unsigned int seed)
{
	gepard_rand_seed = seed;
}

inline unsigned int gepard_rand()
{
	return (((gepard_rand_seed = gepard_rand_seed * 214013L + 2531011L) >> 16) & 0x7fff);
}

void gepard_session_init(int fd, unsigned int recv_key, unsigned int send_key, unsigned int sync_key)
{
	uint32 i;
	uint8 random_1 = RAND_1_START;
	uint8 random_2 = RAND_2_START;

	session[fd]->recv_crypt.pos_1 = session[fd]->send_crypt.pos_1 = session[fd]->sync_crypt.pos_1 = POS_1_START;
	session[fd]->recv_crypt.pos_2 = session[fd]->send_crypt.pos_2 = session[fd]->sync_crypt.pos_2 = POS_2_START;
	session[fd]->recv_crypt.pos_3 = session[fd]->send_crypt.pos_3 = session[fd]->sync_crypt.pos_3 = 0;

	gepard_srand(recv_key ^ SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (8 * random_2) + 5;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (6 * random_1) - 2;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->recv_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(send_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (7 * random_2) - 2;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (2 * random_1) + 9;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->send_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(sync_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (4 * random_2) - 9;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (3 * random_1) - 5;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->sync_crypt.key[i] = random_1;
	}
}

void gepard_init(int fd, uint16 server_type)
{
	const uint16 init_packet_size = 20;
	uint16 recv_key = (gepard_rand() % 0xFFFF);
	uint16 send_key = (gepard_rand() % 0xFFFF);
	uint16 sync_key = (gepard_rand() % 0xFFFF);

	gepard_srand((unsigned)time(NULL) ^ clock());

	WFIFOHEAD(fd, init_packet_size);
	WFIFOW(fd, 0) = SC_GEPARD_INIT;
	WFIFOW(fd, 2) = init_packet_size;
	WFIFOW(fd, 4) = recv_key;
	WFIFOW(fd, 6) = send_key;
	WFIFOW(fd, 8) = server_type;
	WFIFOL(fd, 10) = GEPARD_ID;
	WFIFOL(fd, 14) = min_allowed_gepard_version;
	WFIFOW(fd, 18) = sync_key;
	WFIFOSET(fd, init_packet_size);

	gepard_session_init(fd, recv_key, send_key, sync_key);
}

void gepard_enc_dec(uint8* in_data, uint8* out_data, uint32 data_size, struct gepard_crypt_link* link)
{	
	uint32 i;

	for(i = 0; i < data_size; ++i)
	{
		link->pos_1 += link->key[link->pos_3 % (KEY_SIZE-1)];
		link->pos_2 -= (74 + link->pos_1) * 7;
		link->key[link->pos_2 % (KEY_SIZE-1)] ^= link->pos_1;
		link->pos_1 += (link->pos_2 - link->pos_3) / 4;
		link->key[link->pos_3 % (KEY_SIZE-1)] ^= link->pos_1;
		out_data[i] = in_data[i] ^ link->pos_1;
		link->pos_1 -= 26;
		link->pos_2 -= data_size % 0xFF;
		link->pos_3++;
	}
}

void gepard_send_info(int fd, unsigned short info_type, char* message)
{
	int message_len = strlen(message) + 1;
	int packet_len = 2 + 2 + 2 + message_len;

	WFIFOHEAD(fd, packet_len);
	WFIFOW(fd, 0) = SC_GEPARD_INFO;
	WFIFOW(fd, 2) = packet_len;
	WFIFOW(fd, 4) = info_type;
	safestrncpy((char*)WFIFOP(fd, 6), message, message_len);
	WFIFOSET(fd, packet_len);
}
