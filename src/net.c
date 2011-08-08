/*
 *      net.c
 *      
 *      Copyright 2008 Giorgio "Dani" G. <dani@slacky.it>
 *      Copyright 2011 Shark <shark@slackyd.it>
 *      
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *      
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *      
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 */

#include "slackyd.h"

#define HTTP_TEMPLATE   \
"GET /%s HTTP/1.1\r\n"  \
"Host: %s\r\n"          \
"Accept: text/xml,application/xml,application/xhtml+xml,"  \
"text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n" \
"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"       \
"Connection: close\r\n" \
"\r\n"

#define __act(cond, rval, msg) if (!(cond)) { return shutdown_net_t (netpolicy, rval, msg); }
#define NETSTAT_INIT  -1
#define NETSTAT_END    1

/* read (and ignore) http header received from socket...
 * Return -1 if find 404 not found, else return size of required object.*/
static int
read_http_header (int sd)
{
    char buffer[BUFFSIZE0] = { 0 }, *ptr;
    unsigned i = 0, cnt = 0;

    /* receive data while occured "\r\n\r\n" */
    while (cnt != 4
     && i < BUFFSIZE
     && recv(sd, &buffer[i], 1, 0) > 0)
    {
        if (buffer[i] == '\r' || buffer[i] == '\n')
         cnt++;
        else
         cnt = 0;
        i++;
    }

    if (strstr (buffer, "404 Not Found"))
	 return -1;

    if ((ptr = strstr(buffer, "Content-Length: ")))
	 return atoi(ptr + strlen("Content-Length: "));

    return 0;
}

/* If timeout is minor or equal to 0 use traditional connect()
 * over blocking socket, else set `sockfd' in non-blocking mode 
 * and try to connect socket.
*/
static int
t_connect (int sockfd, void *serv_addr, socklen_t addrlen, u_short timeout)
{
    int rval = 0;
	unsigned long  u_sec = 0;
    const unsigned short pause = 2;
    const unsigned long  USEC  = 100000;

    if (timeout <= 0) return connect (sockfd, serv_addr, addrlen);

    slassert (fcntl(sockfd, F_SETFL, O_NONBLOCK) >= 0);
    
    while (1)
    {
    	rval = connect (sockfd, serv_addr, addrlen);
    	
    	if (!rval)
    	{
    		break;		/* success */
		}
		else
		if (rval < 0 && errno != EINPROGRESS && errno != EALREADY)
		{
			return -1;
		}
		else
		if ((u_sec / (10 * USEC)) >= timeout) /* timeout is in second */
		{
			errno = ETIMEDOUT;
			return -1;
		}
		
		usleep (pause * USEC);
		u_sec += (pause * USEC);
    }

    slassert (fcntl (sockfd, F_SETFL, 0) >= 0);
    return 0;
}

/* Receive data from socket `sd' saving it in `data' big `datasz' bytes.
 */
static int
t_recv (int sd, char *data, size_t datasz)
{
    fd_set read_set;
    struct timeval timeout;
    int rval;
    const int maxtimeout = opt.TIMEOUT;

    memset (data, 0, datasz);

    if (maxtimeout <= 0) /* no timeout, return default recv() */
     return recv (sd, data, datasz, 0);
     
    while (1)
    {
        FD_ZERO(&read_set);
	    FD_SET(sd, &read_set);
	    timeout.tv_sec  = maxtimeout;
        timeout.tv_usec = 0x00;
        
	    rval = select (sd + 1, &read_set, NULL, NULL, &timeout);
    
        if (rval < 0)
        {
            fprintf (stderr, "\n\nselect() error: %s.\n\n", strerror (errno));
            abort();
        }
        else
        if (rval == 0)
	    {
            errno = ETIMEDOUT;
            return -1;
        }
        else
        if (rval > 0)
        {
            return recv (sd, data, datasz, 0);
	    }
    }

    slassert (NULL); /* never here */
    return -1;
}


static void
checkstamp (net_t *netpolicy, int sd)
{
    FILE *fd = NULL;
    int rval;

    memset (netpolicy->stampdata, 0, STAMPSZ0);
    memset (netpolicy->stamprecv, 0, STAMPSZ0);
    
    netpolicy->oldstamp = -1;

    if (!netpolicy->checkstamp
     || !(fd = fopen (netpolicy->destpath, "rb")))
    {
        return;
    }

    rval = fread (netpolicy->stampdata, 1, STAMPSZ, fd);
         
    fclose (fd);
        
    if (rval != STAMPSZ
     || recv (sd, netpolicy->stamprecv, STAMPSZ, 0) != STAMPSZ)
    {
        memset (netpolicy->stampdata, 0, STAMPSZ0);
        memset (netpolicy->stamprecv, 0, STAMPSZ0);
        return;
    }
    
    netpolicy->oldstamp =
    (!memcmp (netpolicy->stampdata, netpolicy->stamprecv, STAMPSZ)) ? 0 : 1;

    return ;
}


static char *
netstat (int init, time_t pause, unsigned long received, unsigned long filesz)
{
    const char cleanlim[] = "     \b\b\b\b\b";
    static char buffer[WORDSIZE0];
    static struct timeval init_time, current_time, last_time;
    static float elapsed, downstream;
    unsigned short percentage;

    if (init == NETSTAT_INIT) {
        gettimeofday (&init_time, NULL);
        last_time  = init_time;
        downstream = 0;
        memset (buffer, 0, WORDSIZE0);
        return NULL;
    }

    gettimeofday (&current_time, NULL);
    elapsed    = current_time.tv_sec - init_time.tv_sec + ((float)current_time.tv_usec / 1000000);
    percentage = ((float)received * 100 / (float)filesz); /* downloaded part */

    if (init == NETSTAT_END || current_time.tv_sec - last_time.tv_sec >= pause)
    {
        downstream = ((float)received / ((elapsed > 0) ? elapsed : 1)) / 1024; /* KBytes */
        last_time = current_time; /* last downstream update */
    }

    snprintf (buffer, WORDSIZE, "%u %% @ %.1f KB/s%s",
        percentage, downstream, cleanlim);

    return buffer;
}

int
get_file_over_wget (net_t *netpolicy,bool is_http)
{
	char buffer[BUFFSIZE0];
	int out;
	fprintf (stdout, "%s...", netpolicy->msg);
        fflush (stdout);
        if(is_http){
		snprintf(buffer,BUFFSIZE, "/usr/bin/wget -q -O '%s' 'http://%s:%d/%s'",
                    netpolicy->destpath, netpolicy->hostname, netpolicy->port, netpolicy->srcpath);
	}else{
		snprintf(buffer,BUFFSIZE, "/usr/bin/wget -q -O '%s' 'ftp://%s:%d/%s'",
                    netpolicy->destpath, netpolicy->hostname, netpolicy->port, netpolicy->srcpath);
	}
        out=system(buffer);
	if(out==0){
		return shutdown_net_t(netpolicy, FILE_DOWNLOADED, "ok");
	}else{
		return shutdown_net_t(netpolicy, out, "Wget Error!");
	}
}
    
int
get_file_over_http (net_t *netpolicy)
{
    char buffer[HUGE0];
    unsigned long received, filesz;
    int rval;
    struct stat st;
    struct hostent *phostent;
    struct sockaddr_in client;

    slassert (netpolicy != NULL);

    fprintf (stdout, netpolicy->msg);
    fflush (stdout);

    /* sanity check */
    if (!netpolicy->savepart)
	 slassert (!netpolicy->checkstamp);

    if (!netpolicy->overwrite &&
        file_exist (netpolicy->destpath, &st, true)) /* regular file exist */
    {
        return shutdown_net_t (netpolicy, FILE_DOWNLOADED, "Already downloaded");
    }

    __act (phostent = gethostbyname (netpolicy->hostname), -1, "Cannot resolve host");
    
    client.sin_family = phostent->h_addrtype;
    client.sin_port   = htons ((unsigned short) netpolicy->port);
    memcpy (&client.sin_addr.s_addr, phostent->h_addr_list[0], phostent->h_length);

    __act ((netpolicy->sd = socket (client.sin_family, SOCK_STREAM, 0)) >= 0, -1, NULL);
    
    __act (!t_connect
    (netpolicy->sd, (struct sockaddr *)&client, sizeof client, netpolicy->timeout), -1, NULL);
    
    snprintf (buffer, HUGE, HTTP_TEMPLATE, netpolicy->srcpath, netpolicy->hostname);
    __act (send
    (netpolicy->sd, buffer, strlen(buffer), 0) == (int) strlen(buffer), -1, NULL);
    
    /* receive http header and save to `filesz' length of file required */
    __act ((rval = read_http_header (netpolicy->sd)) > 0, FILE_NOT_DOWNLOADED, "File Not Found");
    

    filesz = (unsigned long) rval;
    checkstamp (netpolicy, netpolicy->sd);

    __act (netpolicy->oldstamp != 0, FILE_ALREADY_UPDATE, "Already update");
    
    if (netpolicy->savepart)
    {
        slassert ((strlen (netpolicy->destpath) + strlen (".part")) < sizeof (netpolicy->destpath));
        strcat (netpolicy->destpath, ".part");
    }

    __act (netpolicy->fddest = fopen (netpolicy->destpath, "wb"), -1, netpolicy->destpath);
    
    
    if (netpolicy->oldstamp == 1)
    {
       fwrite (netpolicy->stamprecv, 1, STAMPSZ, netpolicy->fddest);
    }

    received = (netpolicy->checkstamp) ? STAMPSZ : 0;

    netstat (NETSTAT_INIT, 0, 0, 0); /* init */
    while ((rval = recv (netpolicy->sd, buffer, HUGE, 0)) > 0)
    {
        received += rval;
        fprintf (stdout, "\r%s [%s]", netpolicy->msg, netstat (0, 1, received, filesz));
        fflush (stdout);
        fwrite (buffer, 1, rval, netpolicy->fddest);
    }
    fprintf (stdout, "\r%s [%s]\n",
        netpolicy->msg, netstat (NETSTAT_END, 1, received, filesz)); /* finish, flush 100% */
    fflush (stdout);
    
    return shutdown_net_t (netpolicy, 0, NULL);
}

/* Send a ftp command `act' and receive ftp reply.
 * If `act' is NULL nothing will be sent.
 * Return 0 if our reply match to "XXX .*\r\n" where XXX
 * is expected_reply *__follow by a space!!!__*.
 * Otherwise return recursively and receive other data.
 */
static int
ftp_act (net_t *netpolicy, const char *act, const char *expected_reply)
{
    int l, r, rval, ftpsz = sizeof (netpolicy->ftpreply);
    char *ptr, buffer[WORDSIZE0];

    if (act)
    {
        l = strlen (act);
        if (send (netpolicy->sd, act, l, 0) != l)
         return -1;
    }
    
    if ((rval = t_recv (netpolicy->sd, netpolicy->ftpreply, ftpsz)) <= 0)
     return -1;

    netpolicy->ftpreply[rval] = 0x00;

    if (rval < (l = strlen (expected_reply)))
     return -1;

    r = strlen (netpolicy->ftpreply);

    if (strncmp (netpolicy->ftpreply, expected_reply, l) == 0
     && netpolicy->ftpreply[l] == ' '
     && netpolicy->ftpreply[r - 2] == '\r'
     && netpolicy->ftpreply[r - 1] == '\n')
    {
        return 0;
    }
    else
    {
        snprintf (buffer, WORDSIZE, "\r\n%s ", expected_reply);
        if ((ptr = strstr (netpolicy->ftpreply, buffer)))
        {
            r = strlen (ptr);
            return 
            (ptr[l + 2] == ' ' && !strcmp (ptr + r - 2, "\r\n")) ? 0 : -1;
        }
        else
        {
            if (atoi (netpolicy->ftpreply) != 550) /* file not found */
             return ftp_act (netpolicy, NULL, expected_reply); /* try next data ... */
        }
    }

    return -1;
}


int
get_file_over_ftp (net_t *netpolicy)
{
    char buffer [HUGE0], *ptr;
    struct hostent *phostent;
    struct sockaddr_in client, pasvclient;
    int rval;
    unsigned long filesz, received;
        
    slassert (netpolicy != NULL);

    fprintf (stdout, netpolicy->msg);
    fflush (stdout);

    if (!netpolicy->savepart) slassert (!netpolicy->checkstamp);

    if (!netpolicy->overwrite &&
        file_exist (netpolicy->destpath, NULL, true)) /* regular file exist */
    {
        return shutdown_net_t (netpolicy, FILE_DOWNLOADED, "Already downloaded");
    }    

    __act (phostent = gethostbyname (netpolicy->hostname), -1, "Cannot resolve host");
  
    client.sin_family = phostent->h_addrtype;
    client.sin_port   = htons ((unsigned short) netpolicy->port);
    memcpy (&client.sin_addr.s_addr, phostent->h_addr_list[0], phostent->h_length);

    __act ((netpolicy->sd = socket (client.sin_family, SOCK_STREAM, 0)) >= 0, -1, NULL);

    __act ((rval = t_connect
     (netpolicy->sd, (struct sockaddr *)&client, sizeof client, netpolicy->timeout)) >= 0, -1, NULL);

    /* starting FTP transaction */
    fprintf (stdout, "\r%s [Starting ftp transaction]", netpolicy->msg);
    fflush (stdout);

    netpolicy->ftpquit = true;

    /* read server ready */
    __act (t_recv (netpolicy->sd, buffer, HUGE) >= 0, FILE_NOT_DOWNLOADED, "Server not ready");

    __act (strncmp (buffer, "220", 3) == 0, FILE_NOT_DOWNLOADED, "Server not ready");
    
    /* anonymous login */
    clrline (stdout, strlen (netpolicy->msg) + 30);
    fprintf (stdout, "\r%s [FTP anonymous login]", netpolicy->msg);
    fflush (stdout);

    /* sending username */
    __act (!ftp_act (netpolicy, "USER anonymous\r\n", "331"), FILE_NOT_DOWNLOADED, "User failed");
    
    /* sending pass */
    __act (!ftp_act (netpolicy, "PASS slackyd@anonymous.org\r\n", "230"), FILE_NOT_DOWNLOADED, "Pass failed");

    clrline (stdout, strlen (netpolicy->msg) + 25);
    fprintf (stdout, "\r%s [Retrieving file]", netpolicy->msg);
    fflush (stdout);
    
    __act (!ftp_act (netpolicy, "SYST\r\n", "215"),   FILE_NOT_DOWNLOADED, "Syst error");
    __act (!ftp_act (netpolicy, "TYPE I\r\n", "200"), FILE_NOT_DOWNLOADED, "Type I error");
    __act (!ftp_act (netpolicy, "PASV\r\n", "227"),   FILE_NOT_DOWNLOADED, "Pasv error");
    
    /* obtain ip and port on passive mode */
    __act (ptr = strchr (netpolicy->ftpreply, '('), FILE_NOT_DOWNLOADED, "Error on pasv mode");
    
    sscanf (ptr, "(%hu,%hu,%hu,%hu,%hu,%hu)",
        &netpolicy->pasv[0], &netpolicy->pasv[1],	/* IP */
        &netpolicy->pasv[2], &netpolicy->pasv[3],	/* IP */
	    &netpolicy->pasv[4], &netpolicy->pasv[5]);	/* port: pasv[4] * 256 + pasv[5] */

    snprintf (netpolicy->pasvip, sizeof netpolicy->pasvip, "%hu.%hu.%hu.%hu",
        netpolicy->pasv[0], netpolicy->pasv[1], netpolicy->pasv[2], netpolicy->pasv[3]);
    
    netpolicy->pasvport = netpolicy->pasv[4] * 256 + netpolicy->pasv[5];

    netpolicy->pasvsd     = socket (AF_INET, SOCK_STREAM, 0);
    pasvclient.sin_family = AF_INET;
    pasvclient.sin_port   = htons((unsigned short) netpolicy->pasvport);

    __act (inet_pton (AF_INET, netpolicy->pasvip, &pasvclient.sin_addr) == 1 &&
           !t_connect (netpolicy->pasvsd, (struct sockaddr *) &pasvclient, sizeof pasvclient, netpolicy->timeout),
           -1, "ftp pasv error");
  
    snprintf (buffer, HUGE, "SIZE %s\r\n", netpolicy->srcpath);
    __act (!ftp_act (netpolicy, buffer, "213"), FILE_NOT_DOWNLOADED,
          (atoi (netpolicy->ftpreply) == 550) ? "File not found" : "Size error");

    filesz = atoi (netpolicy->ftpreply + 4);	/* 4 = strlen ("213 ") */

    /* require file */
    snprintf (buffer, HUGE, "RETR %s\r\n", netpolicy->srcpath);
    __act (!ftp_act (netpolicy, buffer, "150"), FILE_NOT_DOWNLOADED, "Retr error");
    
    checkstamp (netpolicy, netpolicy->pasvsd);

    __act (netpolicy->oldstamp != 0, FILE_ALREADY_UPDATE, "Already update");
       
    if (netpolicy->savepart)
    {
        slassert ((strlen (netpolicy->destpath) + strlen (".part")) < sizeof (netpolicy->destpath));
        strcat (netpolicy->destpath, ".part");
    }

    __act (netpolicy->fddest = fopen (netpolicy->destpath, "wb"), -1, netpolicy->destpath);

    if (netpolicy->oldstamp == 1)
    {
        fwrite (netpolicy->stamprecv, 1, STAMPSZ, netpolicy->fddest);
    }

    received = (netpolicy->checkstamp) ? STAMPSZ : 0;

    clrline (stdout, strlen (netpolicy->msg) + 25);
    netstat (NETSTAT_INIT, 0, 0, 0); /* init */
    while ((rval = recv (netpolicy->pasvsd, buffer, HUGE, 0)) > 0)
    {
        received += (unsigned long) rval;
        fprintf (stdout, "\r%s [%s]", netpolicy->msg, netstat (0, 1, received, filesz));
        fflush (stdout);
        fwrite (buffer, 1, rval, netpolicy->fddest);
    }
    fprintf (stdout, "\r%s [%s]\n",
        netpolicy->msg, netstat (NETSTAT_END, 1, received, filesz)); /* finish, flush 100% */
    fflush (stdout);
    
    return shutdown_net_t (netpolicy, 0, NULL);
}

/* Get a file from another point of filesystem =D and copy
 * it into slackyd's dir.
 */
int get_file_over_fs (net_t *netpolicy)
{
    const char *destpath = netpolicy->destpath;
	const char *hostname = netpolicy->hostname;
	const char *message  = netpolicy->msg;
	char srcpath[BUFFSIZE0];
	char buffer[HUGE0];
		
    FILE *fdsrc = NULL;
    int rval;
    
    slassert (netpolicy != NULL);

	/* Fix local path:
	 * If we are using a local mirror, hostname will be base path.
	 * Ex: using mirror "/mnt/data/slackware/" `hostname' will be "mnt".
	 */ 
	snprintf (srcpath, BUFFSIZE, "/%s/%s", hostname, netpolicy->srcpath);

	fprintf (stdout, message);
    fflush (stdout);

    if (!netpolicy->savepart)
     slassert (!netpolicy->checkstamp);

    /* check for overwrite */
    if (!netpolicy->overwrite &&
        file_exist (destpath, NULL, true)) /* regular file exist */
    {
        return shutdown_net_t (netpolicy, FILE_DOWNLOADED, "Already downloaded");
    }

	/* Check for timestamp */
    if (netpolicy->checkstamp
     && (fdsrc = fopen (srcpath, "rb"))
     && (netpolicy->fddest = fopen (destpath, "rb"))
     && fread (netpolicy->stampdata, 1, STAMPSZ, fdsrc) == STAMPSZ
     && fread (netpolicy->stamprecv, 1, STAMPSZ, netpolicy->fddest) == STAMPSZ
     && memcmp (netpolicy->stampdata, netpolicy->stamprecv, STAMPSZ) == 0)
    {
        fclose (fdsrc);
        return shutdown_net_t (netpolicy, FILE_ALREADY_UPDATE, "Already update");
    }
    if (fdsrc) fclose (fdsrc); 
    if (netpolicy->fddest) fclose (netpolicy->fddest);
    
    netpolicy->fddest = fopen (destpath, "wb");
    __act (netpolicy->fddest, -1, destpath);

    __act (fdsrc = fopen (srcpath, "rb"), -1, srcpath);

    
    while ((rval = fread (buffer, 1, HUGE, fdsrc)) > 0)
    {
        fwrite (buffer, 1, rval, netpolicy->fddest);
    }
    
    fclose (fdsrc);
    return shutdown_net_t (netpolicy, FILE_DOWNLOADED, "done");
}

    
/* require `package' from N_REPO repository already load from config file */
int
get_pkg (pkg_t *package)
{
    const char *cache = opt.dest;
    int r = package->N_REPO;
    net_t netpolicy;
    char *loc, *name, *host, *path;
    
    slassert (package != NULL);

    loc  = package->location;
    name = package->name;
    host = REPOS[r].hostname;
    path = REPOS[r].path;

    init_net_t (&netpolicy, REPOS[r].proto_t, REPOS[r].port);
    netpolicy.savepart   = true;
    netpolicy.overwrite  = false;
    netpolicy.checkstamp = false;
    strncpy (netpolicy.hostname, host, BUFFSIZE);
    snprintf (netpolicy.msg, BUFFSIZE, "%s %s/%s.",
        (REPOS[r].proto_t == proto_file) ? "Copying to" : "Downloading to", cache, name);
    snprintf (netpolicy.srcpath,  BUFFSIZE, "%s/%s/%s", path, loc, name);
    snprintf (netpolicy.destpath, BUFFSIZE, "%s/%s", cache, name);

    if(opt.wget){ 
	    switch (REPOS[r].proto_t) {
		case proto_http: return get_file_over_wget (&netpolicy,true);  break;
		case proto_ftp:  return get_file_over_wget (&netpolicy,false);  break;
		case proto_file: return get_file_over_fs   (&netpolicy);  break;
		default:   slassert (NULL);                               break;
	    }
    }else{
	    switch (REPOS[r].proto_t) {
		case proto_http: return get_file_over_http (&netpolicy);  break;
		case proto_ftp:  return get_file_over_ftp  (&netpolicy);  break;
		case proto_file: return get_file_over_fs   (&netpolicy);  break;
		default:   slassert (NULL);                               break;
		}
    }

    return -1;
}
