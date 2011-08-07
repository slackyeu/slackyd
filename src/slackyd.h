 
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
#define _GNU_SOURCE
#define SLACKYD_VERSION "1.0"

#define DATADIR     "/var/slackyd"
#define CONFIGFILE  "/etc/slackyd/slackyd.conf"
#define PKGDIR      "/var/log/packages"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <regex.h>
#include <stdarg.h>
#include <getopt.h>
#include <elf.h>
#include <bzlib.h>
#if defined MTRACE
 #include <mcheck.h>
#endif

#include "global.h"

#define HUGE        8192
#define HUGE0       (HUGE + 1)
#define BUFFSIZE    1024
#define BUFFSIZE0   (BUFFSIZE + 1)
#define WORDSIZE    256
#define WORDSIZE0   (WORDSIZE + 1)

#define PKG_NAME     "PACKAGE NAME:"
#define _PKG_NAME    0x00
#define PKG_LOC      "PACKAGE LOCATION:"
#define _PKG_LOC     0x01
#define PKG_SIZE_C   "PACKAGE SIZE \\(compressed\\):"
#define _PKG_SIZE_C  0x02
#define PKG_SIZE_U   "PACKAGE SIZE \\(uncompressed\\):"
#define _PKG_SIZE_U  0x03
#define PKG_REQ      "PACKAGE REQUIRED:"
#define _PKG_REQ     0x04
#define PKG_CNFLT    "PACKAGE CONFLICTS:"
#define _PKG_CNFLT   0x05
#define PKG_SGST     "PACKAGE SUGGESTS:"
#define _PKG_SGST    0x06
#define PKG_DESC     "PACKAGE DESCRIPTION:"
#define _PKG_DESC    0x07

#define FILELIST            "FILELIST.TXT"
#define PACKAGES            "PACKAGES.TXT"
#define CHECKSUMS           "CHECKSUMS.md5"
#define MANIFEST            "MANIFEST"
#define ZMANIFEST           "MANIFEST.bz2"
#define SMANIFEST           "slackware/MANIFEST.bz2"
#define SMANIFEST64         "slackware64/MANIFEST.bz2"

#define MATCH_ALL_NAME              0x00
#define MATCH_EXACTLY_NAME          0x01
#define MATCH_EXACTLY_PACKAGE       0x02
#define MATCH_USING_REGEX           0x03
#define MATCH_ALL_NAME_INST         0x04
#define MATCH_EXACTLY_NAME_INST     0x05
#define MATCH_EXACTLY_PACKAGE_INST  0x06
#define MATCH_ALL_NAME_BLACK        0x07
#define MATCH_ALL_NAME_BLACK_REG    0x08

#define FEATURE_UNAVAILABLE           -2
#define FEATURE_DISABLED              -1
#define FEATURE_NOTHING_SPEC           0

#define PACKAGE_STATUS_NOT_CHECKED    -3
#define PACKAGE_STATUS_NOT_INSTALLED  -2
#define PACKAGE_STATUS_INSTALLED      -1

#define VERSION_ALL              -1
#define VERSION_MINOR            0x00
#define VERSION_MINOR_OR_EQUAL   0x01
#define VERSION_EQUAL            0x02
#define VERSION_MAJOR            0x03
#define VERSION_MAJOR_OR_EQUAL   0x04

#define FILE_DOWNLOADED          0x00
#define FILE_ALREADY_UPDATE      0x01
#define FILE_NOT_DOWNLOADED      0x02

#define PKGLIST_CHECK_QUIT_NEVER   0x00
#define PKGLIST_CHECK_QUIT_ALWAIS  0x01
#define PKGLIST_CHECK_QUIT_ON_ALL  0x02

#define DEP_T_REQUIRED        0x00
#define DEP_T_SUGGESTED       0x01
#define DEP_T_CONFLICT        0x02
#define DEP_T_REQUIRED_MISS   0x03
#define DEP_T_SUGGESTED_MISS  0x04

#define PURGE_PKG   0x01
#define PURGE_ALL   0x02

#define STAMPSZ0   126
#define STAMPSZ    (STAMPSZ0 - 1) 
typedef struct net_t {
    int sd;
    bool ftpquit;
    char hostname[BUFFSIZE0];
    char ftpreply[BUFFSIZE0];
    unsigned port;
    unsigned timeout;

    bool checkstamp;
    bool overwrite;
    bool savepart;
    int oldstamp;

    char msg      [BUFFSIZE0];
    char stampdata[STAMPSZ0];
    char stamprecv[STAMPSZ0];
    char destpath [BUFFSIZE0];
    char srcpath  [BUFFSIZE0];
    FILE *fddest;

    int pasvsd;
    unsigned short pasv[6];
    char pasvip[20];
    unsigned pasvport;
} net_t;


typedef enum {			/* entry for package origin tracking   */
    _PATCHES,			/* security fix package */
    _PACKAGES,			/* default package      */
    _EXTRA,				/* extra package        */
    BRANCHES			/* number of branch, 3  */
} branches;


/* packages required, suggested or conflicts */
typedef struct {
    char *name;
    char op[3];
    char op_t;
    char *version;

	unsigned char type;
	bool OR_next;
	bool missing;
	
} dep_t;

/* struct for repository packages info */
typedef struct {
    char *name;
    char *location;
    int size_c;
    int size_u;

    dep_t *required,
          *conflicts,
          *suggests;

    int nrequired,
        nconflicts,
        nsuggests;
    
    char *desc;
    
    u_short N_REPO;		/* repository that containe package    */
    branches branch;
	
    pkg_struct pstruct;

    int status;
    char *installed;
    char blacklisted;
	
} pkg_t;

struct dlist {
    char *s;
    struct dlist *next;
};
typedef struct dlist dlist;

struct pkg_t__list {
    pkg_t *p;
    struct pkg_t__list *next;
};
typedef struct pkg_t__list pkg_l;

typedef struct choose_dep_t {
	pkg_l *added;
	pkg_t **next;
	unsigned nnext;
} choose_dep_t;
	
/* struct for packages build sources */
typedef enum {
    reg_1, /* regex ".../source/.../<pkgname>/" or ".../source/<pkgname>/" */
    reg_2, /* regex ".../<pkgname>/<pkgversion>/src/" */
    reg_n  /* number of possible regex used to find a package build sources */
} srcreg_t;
typedef struct {
    pkg_t *package;
    dlist *paths;
    dlist *files;
    dlist *rpaths;
    srcreg_t regtype;
} pkgsrc_t;


/* struct for upgrade */
typedef struct {
    char  *local;
    pkg_t **remote;
    unsigned sub_new;
} upgrade_t;


typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Ehdr Elf32_Header;
    Elf64_Ehdr Elf64_Header;
    Elf32_Shdr *Elf32_SectionHeader;
    Elf64_Shdr *Elf64_SectionHeader;
    Elf32_Dyn *Elf32_DynamicSection;
    Elf64_Dyn *Elf64_DynamicSection;

    unsigned long strtab_off;
    unsigned short dyn_index;
    unsigned short dyn_entries;
    char *rpath;

} ElfData;

#define NEEDSIZE  WORDSIZE
#define NEEDSIZE0 WORDSIZE0
#define INDEXES   255
	
typedef struct {
    char needed[NEEDSIZE0]; /* missing shared object                        */
    dlist *pkgname;         /* package(s) name that require `needed'        */
    dlist *object;          /* object(s) of `pkgname' that require `needed' */
    pkg_l *packages;        /* packages that containe `needed' */
} libneed_t;



#define RS_COMPRESSED   0
#define RS_UNCOMPRESSED 1
typedef struct {
    bool slackware;
    char rname[BUFFSIZE0];
    char raddr[BUFFSIZE0];
    unsigned n_packages;
    unsigned packages_sz[2];
    unsigned n_patches;
    unsigned patches_sz[2];
    unsigned n_extra;
    unsigned extra_sz[2];

    unsigned n_total;
    unsigned total_sz[2];
} rstat_t;



/* main funcs */
void usage
	(char* prgname);

/* md5.c */
char *getmd5
    (const char *file, const char *checksum_path);
void md5file
    (char *filename, char *checksum, const char *md5list);

/* func.c */
void _error
	(u_short N, ...);
void clrbuff
	(void);
void clrline
	(FILE * stream, u_short c);
void printfv
    (const char *format, ...);
void printfw
    (const char *format, ...);
void * xmalloc
	(size_t size);
void * xcalloc
	(size_t nmemb, size_t size);
void * xrealloc
	(void *ptr, size_t size);
char * xstrdup
	(const char *s);
char * xstrndup
    (const char *s, size_t n);
void rmkdir
	(const char *path, mode_t mode);
void filepath
    (const char *dest);
bool file_exist
    (const char *path, struct stat *statptr, bool must_be_reg);
void xregcomp
    (regex_t *preg, const char *regex, int cflags);

int movestrlim
    (char *src[], const char *delim, short policy);
const char* set_regex
    (const char *name);
char* strregdup
    (char *s, regmatch_t match, unsigned addoff);

unsigned rmdir_rf
	(const char *path, bool void_dir);
int emptydir
    (const char *dir, const char *ext);
FILE* fopen_or_die
	(const char *file_name, const char *mode);
size_t get_file_size
	(FILE * fd);
void fdload
	(char **data, FILE * fd, size_t size);
bool fsload
	(const char *path, char **dest);
int parse_options
	(int argc, char **argv);

/* function to manage slackyd types */
/*----------------------------------*/
void dlist_add
    (dlist **list, char *s);
void dlist_free
    (dlist **list);
unsigned dlist_count
    (dlist *list);
bool dlist_check
    (dlist *list, const char *s);
void dlist_print
    (dlist *list, const char *delim1, const char *delim2);
void pkgl_add
    (pkg_l **pkglist, pkg_t *pkg);
void pkgl_free
    (pkg_l **pkglist);
unsigned pkgl_count
    (pkg_l *pkglist);
void pkgl_join
    (pkg_l **head, pkg_l *end);
void pkgl_print
    (pkg_l *pkglist, const char *delim1, const char *delim2);
bool pkgl_check
    (const char *pkgname, pkg_l *pkglist, int flag);
pkg_t **pkgl2pkgt
    (pkg_l *pkglist, unsigned *n);
void init_net_t
    (net_t *netpolicy, protocol_t p, unsigned port);
int shutdown_net_t
    (net_t *netpolicy, int rval, const char *msg);
int is_installed
    (const char *name, int cflags, unsigned start);
bool pkg_t_check
    (const char *name, pkg_t *packages[], unsigned npackages, int flag);
void add_dep
    (const char *name, const char *op, const char *version, u_char type, dep_t **dest, int *n);
void add_splist
    (installed_t *sp, const char *name);
pkg_t *pkg_t_dup
	(pkg_t *src);
void pkg_t_add
    (pkg_t **packages[], unsigned *npackages, pkg_t *pnew);
void pkg_t_free
	(pkg_t **addr);
void pkg_t_free_all
	(pkg_t **addr[], unsigned elements);
void free_installed_t
    (installed_t **sp, unsigned n);

void pkg_t_rm
    (pkg_t **packages[], unsigned *npackages, unsigned memb);
/*----------------------------------*/


void parse_config
	(void);
void
    process_lib_path (dlist **path);
int check_elf_libs 
	(dlist *libpath, char *file, libneed_t **missing_libs,
	 unsigned *n_missing_libs, char *tgz);

/* net.c */
int get_file_over_wget
    (net_t *netpolicy, bool is_http);
int get_file_over_http
    (net_t *netpolicy);
int get_file_over_ftp
    (net_t *netpolicy);
int get_file_over_fs
    (net_t *netpolicy);
int get_pkg
	(pkg_t *packages);


/* update.c */
int update
	(void);
int upgrade
	(const char *name);

/* search.c */
int packages_list_check
    (bool verbose, int flags);
pkg_l *save_pkg_data
    (dlist *pkgdata, int r, int b);
int search_pkg
    (dlist **datalist, short set_match, char *path, const char *pkgname);
pkg_l *search
    (short flag, const char *name);
bool required_ok
    (dep_t *required, pkg_t *found);
bool missing_required_ok
    (dep_t *required);
const char *set_regex
	(const char *name);
unsigned installed
    (installed_t **splist);	
void sort_pkg
	(pkg_t **list[], unsigned *n_list);
unsigned search_shared_dep
    (libneed_t *need);


/* packages.c */
char *make_rpath
    (unsigned rindex, branches branch, const char *file);
char *pkg_type
    (pkg_t *package);
int have_missing_req
	(pkg_t *pkg);
int have_missing_sug
	(pkg_t *pkg);
char is_blacklisted
    (const char *name);
void show_pkg_found
    (pkg_t **packages, unsigned n);
void get
	(pkg_t **packages[], unsigned *n_pkgs);
void verify_md5
	(pkg_t *pkgname);
void show_package_info
	(pkg_t *packages[], unsigned n_pkgs);
void show_missing_req
	(pkg_t *packages[], unsigned n_pkgs);
bool split_pkg
	(const char *pkg, pkg_struct * data);
void make_missing_req_list
    (pkg_t *packages[], unsigned packages_found);
void choice_dep
	(choose_dep_t *data, pkg_t *package, int type);
int purge
	(int flag);
void installed_packages
	(const char *name);
dlist *pkglist_official
    (void);
void unofficial_packages
	(const char *name);
void obsolete_packages
	(const char *name);
void blacklisted_packages
	(const char *name);
void replaceable_packages
    (const char *pkgname);
int rstat
    (void);
void search_packager_lib
    (const char *name);
int check_shared_dep
	(const char *pkg);
int pkgsrc_get
    (pkg_t **packages[], unsigned *npackages);

