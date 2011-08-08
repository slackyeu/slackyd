/*
 *      slackyd.h
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

#ifndef SLACKYD_GLOBAL_H

#define SLACKYD_GLOBAL_H

typedef enum bool
{
	false,
	true

} bool;

typedef enum protocol_t
{
	proto_http,
	proto_ftp,
	proto_file

} protocol_t;

/* struct for command line argument */
typedef struct options_t {
    bool force;
    bool update;
    bool upgrade;
    bool search;
    bool view;
    bool get;
    bool getsrc;
    bool buildsrc;
    bool check_dep;
    bool resolve_dep;
    bool notify_dep;
    bool packager_dep;
    bool shared_dep;
    bool installed;
    bool nslack_installed;
    bool obsolete;
    bool replaceable;
    bool rstat;
    bool purge;
    bool purge_all;
    bool hash;
    bool use_regex;
    bool case_insensitive;
    bool verbose;
    bool warn;
    bool print_status;
    bool skip_status;
    bool blacklist;
    bool show_blacklisted;
    bool wget;
    bool slackware64;
    
    u_short enabled;

    char *package;
    char *config;
    char *cache;
    char *dest;
    u_short TIMEOUT;
    regex_t *blacklisted;
    unsigned nblacklisted;
    bool upgrade_replacing_official;
    
} options_t;

options_t opt;


/* struct for identify data to save */
typedef struct pkg_fold
{
    bool size_c;
    bool size_u;
    bool req;
    bool conflict;
    bool suggest;
    bool desc;

} pkg_fold;

pkg_fold p_fold;


/* struct for global data from config file */
typedef struct
{
    char *name;	    /* repository name choosed in slackyd.conf */
    char *hostname;	/* repository hostname */
    char *path;	    /* repository path */
    unsigned port;  /* extra port to connect */
    protocol_t proto_t;  /* repository protocol */
    bool SLACKWARE;		 /* repository type, slackware or extra */

} repositories;

repositories *REPOS;
unsigned      N_REPOS;

#define NAMESIZE     50
#define VERSIONSIZE  30
#define ARCHSIZE     30
#define BUILDSIZE    30
#define PACKAGE_SIZE (NAMESIZE + VERSIONSIZE + ARCHSIZE + BUILDSIZE)
typedef struct
{
    char name   [NAMESIZE    + 1];
    char version[VERSIONSIZE + 1];
    char arch   [ARCHSIZE    + 1];
    char build  [BUILDSIZE   + 1];

} pkg_struct;


/* many functions need a list of installed packages.
 * This global list will save time and resources.
 * On main() will be read all packages installed calling:
 *
 * nginst = installed (&ginst);
 *
 * Other function will use directly ginst and nginst !
 */ 
typedef struct
{
    char *name;
    pkg_struct pstruct;

} installed_t;

installed_t *ginst;
unsigned     nginst;


char * (* xstrstr)
    (const char *haystack, const char *needle);

int (* xstrcmp)
    (const char *s1, const char *s2);

#define slassert(expr) { \
 if (!(expr)) { \
 fprintf (stderr, "\n\nA fatal error occured at line %d of file %s.\n", __LINE__, __FILE__); \
 if (strcmp (#expr, "NULL")) \
  fprintf (stderr, "Unexpected error on expression `"#expr"'.\n"); \
 fprintf (stderr,  "Please report this.\n\n"); \
 abort(); }}

#endif
