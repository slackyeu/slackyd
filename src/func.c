/*
 *      func.c
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

void
_error (u_short N, ...)
{
    register u_short i;
    va_list ap;

    fflush (stdout);
    fflush (stderr);

    va_start (ap, N);
    for (i = 0; i < N; i++)
     fprintf (stderr, "%s", va_arg(ap, char *));
    
    va_end(ap);

    exit(1);
}

void
clrbuff (void)
{
    int c;
    
    while ((c = getc(stdin)) != '\n' && c != EOF)
    ;
}

void
clrline (FILE * stream, u_short c)
{
    int i;

    fputc('\r', stream);

    for (i = 0; i < c; i++)
	 fputc(' ', stream);

    fputc('\r', stream);
    fflush (stream);

    return;
}

void
printfv (const char *format, ...)
{
    va_list list;

    if (!opt.verbose) {
        return ;
    }

    va_start (list, format);

    vfprintf (stdout, format, list);
    
    va_end (list);

    fflush (stdout);

}

void printfw (const char *format, ...)
{
    va_list list;

    if (!opt.warn) {
        return ;
    }

    va_start (list, format);

    vfprintf (stderr, format, list);
    
    va_end (list);

    fflush (stderr);
}

void *
xmalloc (size_t size)
{
    register void *value = malloc (size);
    if (value == 0)
     _error (1, "\nVirtual memory exhausted\n\n");
    return value;
}

void *
xcalloc (size_t nmemb, size_t size)
{
    register void *value = calloc (nmemb, size);
    if (value == 0)
     _error (1, "\n"
     "Virtual memory exhausted\n\n");
    return value;
}

void *
xrealloc (void *ptr, size_t size)
{
    register void *value = realloc (ptr, size);
    if (value == 0)
     _error (1, "\nVirtual memory exhausted\n\n");
    return value;
}

char *
xstrdup (const char *s)
{
    register char *value = (s) ? strdup (s) : NULL;

    if (!s)
     return NULL;

    if (value == 0)
     _error (1, "\nVirtual memory exhausted\n\n");
    return value;
}

char *
xstrndup(const char *s, size_t n)
{
    register char *value = (s) ? strndup (s, n) : NULL;

    if (!s || n < 1)
     return NULL;

    if (value == 0)
     _error (1, "\nVirtual memory exhausted\n\n");
    return value;
}

/* make a directory `path' with permission `mode' */
static void
xmkdir (const char *path, mode_t mode)
{
	struct stat s_stat;
	mode_t mask;
	
	if (stat (path, &s_stat) == 0)
	{
	    if (!S_ISDIR (s_stat.st_mode)) {
            _error (3,"\n\nFatal error.\n", path, " exist and is not a"
            " directory.\nTry to remove.\n\n");
        }
	}
	else
	{
		mask = umask (0000);

        if (mkdir (path, mode) < 0) {
            _error (5, "Cannot create ", path, ": ", strerror (errno), "\n\n");
        }

        umask(mask);
	}
		
	return;
}

/* make recursively directory `path'. */
void
rmkdir (const char *path, mode_t mode)
{
    char *tmp, *tfree, *tok;
    dlist *paths = NULL, *current;
    unsigned i, j = 0;
    struct stat st;

    if (!path || !stat (path, &st)) /* null data or path already exist */
     return;

    tmp   = xmalloc (strlen (path) + 1);
    tfree = tmp;
    strcpy (tmp, path);
    tok   = strtok (tmp, "/");

    while (tok)
	{
        dlist_add (&paths, xstrdup (tok));
        j++;
        tok = strtok (NULL, "/");
    }

    memset (tmp, 0x00, strlen (path));
    current = paths;

    for (i = 0; current && i < j; i++)
	{
        strcat (tmp, "/");
        strcat (tmp, current->s);
        
        switch (file_exist (tmp, &st, false))
		{
            case true:
                if (!S_ISDIR (st.st_mode)) {
                    _error (3,
                    "\n\nError: '", tmp, "` exist but isn't a directory.\n"
                    "Try to remove.\n\n");
                } 
	        	break;
            case false:
                xmkdir (tmp, mode);
                break;
        }

        current = current->next;
    }

    free (tfree);
    dlist_free (&paths);

    return;
}

/* Create path for file `dest' */
void
filepath (const char *dest)
{
    char *p = xstrdup (dest), *ptr = strrchr (p, '/');

    *ptr = 0x00;
    rmkdir (p, 0755);
    free (p);
    
    return;
}
    

void
xregcomp (regex_t *preg, const char *regex, int cflags)
{
    int rval = regcomp (preg, regex, cflags);
    char buffer[BUFFSIZE0];

    if (!rval)
     return; /* success */

    regerror (rval, preg, buffer, BUFFSIZE); 

    _error (5, "\n\nRegex \"", regex, "\" failed: ", buffer, "\n\n");
}

bool
file_exist (const char *path, struct stat *statptr, bool must_be_reg)
{
    struct stat s, *st = (statptr) ? statptr : &s;

    if (!stat (path, st))
    {
		return (must_be_reg && !S_ISREG (st->st_mode)) ? false : true;
    }
    else
    {
        switch (errno)
		{
            case ENOENT:
	    		return false;
				break;
            default:
	    		fprintf (stderr, "\n\n%s: %s\n\n", path, strerror (errno));
	    		exit (1);
				break;
        }
    }
    return 0;
}

/* move base of pointer `src' while (*src)[0] is not a char contained in `delim' string.
 * If `policy' is 0 move only initial characters.
 * If `policy' is 1 move only final characters.
 * If `policy' is 2 move initial and final characters.
 */
int
movestrlim (char *src[], const char *delim, short policy)
{
    unsigned l = 0x00;
    
    if (!src || !delim) {
        return EXIT_FAILURE;
    }

    if (policy == 0 || policy == 2) {
        while (strchr (delim, (*src[0])) != NULL) {
            (*src)++;
        }
    }

    if (policy == 1 || policy == 2) {
        l = strlen (*src) - 1;
        while (strchr (delim, (*src)[l]) != NULL) {
            (*src)[l--] = 0x00;
        }
    }

	return ((*src)[0] && strlen (*src) > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Create regex string `for name'.
 * If occured character some '+' '*' '\' ecc... prefix a '\'  
 */
const char *
set_regex (const char *name)
{
    const char characters[] = "+.-*[]\\";
    static char buffer[BUFFSIZE0];
    unsigned i = 0, l = 0;

    memset (buffer, 0, BUFFSIZE);
    if (!name)
	 return "";
	 
    while (name[i])
    {
        if (strchr (characters, name[i]))
        {
            buffer[l++] = '\\';
        }
        buffer[l++] = name[i++];
    }

    buffer[l] = 0x00;
    return buffer;
}


/* Extract a regex from a string data `s'.
 * Our match start from `match.rm_so` and finish to `match.rm_eo'.
 * They are begin and finish match offset.
 * If addoff is major to zero, add this to start offset: we maybe
 * want skip a part of string reentrant in our match.
 * Example:
 *    "PACKAGE NAME:  packagename-version-arch-build.tgz\n"
 *    In this case we want skip token "PACKAGE NAME:" and move pointer after
 *    initial spaces or tab.
 *
 * This function do it :)
 * Remove also last spaces, tab or newlines.
 *
 * Note: we use always REG_NEWLINE regex flags.
 * Normally our package data is one-line only.
 */
char *
strregdup (char *s, regmatch_t match, unsigned addoff)
{
    int len = match.rm_eo - match.rm_so - addoff;
    char *ptr, *dest = NULL;
    const char startlim[] = "\t ", endlim[] = "\n\t ";
    
    if (s == NULL || len < 1) {
        return NULL;
    }

    ptr = s + match.rm_so + addoff;
    
    while (strchr (startlim, ptr[0]))
    {
        ptr++;
        len--;
    }

    if (!ptr[0] || ptr[0] == '\n' || len < 1) {
        return NULL;
    }
   
    dest = xstrndup (ptr, len);

    /* remove last space char */
	len = strlen (dest);
	while (strchr (endlim, dest[len]))
	 dest[len--] = 0x00;

	return dest;
}

/* empty directory `path', if `void_dir' is true remove also `path' void directory */
unsigned
rmdir_rf (const char *path, bool void_dir)
{
	struct dirent **namelist;
	struct stat s_stat;
	int rval, n;
	char buffer [BUFFSIZE0] = { 0 };
	static unsigned removed = 0;
	
	if ((n = scandir (path, &namelist, 0, alphasort)) < 0)
    {
		if (errno != ENOENT)
		{
            fprintf (stderr, "Error; %s: %s\n", path, strerror (errno));
		}
        return 0;
	}
	
	if (n == 2)
	{ /* empty dir ... */
		if (void_dir)
		{
			rval = remove (path);

            if (!rval) {
			    removed++;
            }
            
			free (namelist[0]);
			free (namelist[1]);
			free (namelist);
            return removed;
		}
		else
		{
			free (namelist[0]);
			free (namelist[1]);
			free (namelist);
			return removed;
		}
	}
	
	while (n-- > 2)
    {
		snprintf (buffer, BUFFSIZE, "%s/%s", path, namelist[n]->d_name);
		
		if (stat (buffer, &s_stat) < 0)
		{
			fprintf (stderr, "\n\nstat() failed on %s: %s\n\n", buffer, strerror (errno));
			continue ;
		}
		
		if (S_ISDIR (s_stat.st_mode))
        {
            rmdir_rf (buffer, true);
        }
		else
		{
			rval = remove (buffer);

            if (!rval)
            {
                removed++;
            }
		}
			
		free (namelist[n]);
	}
	
	if (void_dir && remove (path) != 0)
    {
        fprintf (stdout, "%s: %s\n", path, strerror (errno));
    }
	
	free (namelist[0]);
	free (namelist[1]);
	free (namelist);

	return removed;	
}
	


/* Empty a dir from file with extension `ext'.
 */
int
emptydir (const char *dir, const char *ext)
{
    char buffer[BUFFSIZE0], *ptr;
    struct dirent **namelist;
    struct stat st;
    int n, errors = 0x00, deleted = 0x00;

    n = scandir (dir, &namelist, 0, alphasort);

    if (n < 0 && errno != ENOENT)
    {
        return -1;
    }
    else
    if (n > 2)
    while (n-- > 2)
    {
        snprintf (buffer, BUFFSIZE, "%s/%s", dir, namelist[n]->d_name);

        if (stat (buffer, &st) < 0)
		{
			errors++;
        }
        else
        if (!S_ISDIR (st.st_mode))
        {
            if ((ptr = strrchr (namelist[n]->d_name, '.')))
            {
                if (!strcasecmp (++ptr, ext))
                {
                    if (!remove (buffer))
                    {
                        deleted++;
                    }
                    else
                    {
                        errors++;
                    }
                }
            }
        }
                
        free (namelist[n]);
    }

    free (namelist[1]);
    free (namelist[0]);
    free (namelist);

    return (errors > 0) ? -1 : deleted;
}


/* open file_name in mode `mode', if fail exit */
FILE *
fopen_or_die (const char *file_name, const char *mode)
{
    FILE *fd = NULL;
    fd = fopen (file_name, mode);

    if (!fd) {
		if (*mode == 'w' || *mode == 'a')
	     _error (5, "\n"
	     "Cannot write ", file_name, ": ", strerror (errno), "\n\n");
		else
	     _error (5, "\n"
	     "Cannot open ", file_name, ": ", strerror (errno), "\n\n");
    }

    return fd;
}

/* return size of file fd, stream position will not modified */
size_t
get_file_size (FILE *fd)
{
    long pos = 0,  end = 0;
    int rval;

    if (!fd) {
        return 0;
    }

    /* save current position */
    pos = ftell (fd);
    slassert (pos >= 0);
   
    /* set position at EOF and get size */
    rval = fseek (fd, 0, SEEK_END);
    slassert (!rval);
    end = ftell(fd);
    slassert (end >= 0);
    
    /* restore old position */
    fseek(fd, pos, SEEK_SET);

    /* return size */
    return end;
}

/* save contenent of file `fd', big `size' bytes, in *`data' */
void
fdload (char **data, FILE *fd, size_t size)
{
    if (size <= 0) {
        *data = NULL;
        return;
    }

    *data = (char *) xmalloc((size + 1) * sizeof (char));

    rewind (fd);
    
    if (fread (*data, 1, size, fd) != size)
    _error (3, "\n"
    "Error  on file loading, cannot read all data from file: ", strerror (errno), "\n"
    "Please report this.\n\n");
    	
   return;
}

/* open `path' file and load it in `dest'. */
bool
fsload (const char *path, char **dest)
{
    FILE *fd;

    if (!(fd = fopen (path, "rb")))
	return true;

    fdload (dest, fd, get_file_size(fd));
    fclose (fd);
    
    if (*dest == NULL) {
        return true;
    }
    
    return false;
}


/* +=========================================+
 * | Function to parse config file start
 * +=========================================+
 */

/* Read mirror used during last update and return his index
 * in REPOS[] array, if possible, otherwise return -1.
 */
static int
mirror_get_index (void)
{
    const char *cache = opt.cache;
    int index;
    char buffer[BUFFSIZE0], *hostname = NULL, *path = NULL;
    FILE *fd;

    snprintf (buffer, BUFFSIZE, "%s/slackware/mirror.slackyd", cache);
    /* "[mirror_used_during_update_hostname][mirror_used_during_update_path]" */
    if (!(fd = fopen (buffer, "r")))
     return -1;    

    if (!fgets (buffer, BUFFSIZE, fd))
	{
		fclose (fd);
		return -1;
	}
	
    if (!(hostname = strtok (buffer, "[]"))
    || (!(path = strtok (NULL, "[]"))))
    {
        fclose (fd);
		return -1;
    }

    for (index = 0; (unsigned)index < N_REPOS; index++)
    {
        if (!strcmp (hostname, REPOS[index].hostname)
         && !strcmp (path, REPOS[index].path))
        {
            fclose (fd);
			return index;
        }
    }

	fclose (fd);
	return -1;
}

/* Swap mirror order.
 * Try to find slackware mirror used during last update and
 * move to begin of array.
 * Then if slackyd.conf will be changed, untill future update
 * packages will be take from mirror used since last time...
 */
static void
mirror_fix_order (void)
{
	repositories tmp;
	int last = mirror_get_index ();

	/* If we are updating packages list NOT swap mirror order ! */
	if (opt.update)
	 return;

	if (last >= 0)
	{
		slassert ((unsigned)last < N_REPOS);
		tmp         = REPOS[0];
		REPOS[0]    = REPOS[last];
		REPOS[last] = tmp;
	}
	return;
}


/* check for repositories with same name */
static void
mirror_check (void) {

	unsigned i, j;

	if (!N_REPOS)
	{
		fprintf (stderr, "\nError: no repository in %s.\n\n", opt.config);
		exit (1);
	}
	
	for (i = 0; i < N_REPOS; i++)
	 for (j = 0; j < N_REPOS; j++)
	  if (i != j &&
	      strcmp (REPOS[i].name, REPOS[j].name) == 0 &&
	      strcmp (REPOS[i].name, "slackware")   != 0)
	      _error (3, "\n"
	      "Too repository named \"", REPOS[i].name, "\".\n"
	      "Fix your slackyd.conf.\n\n");
	
	return;
}

static void
cfg_syntax_error (const char *err, unsigned line)
{
	fprintf (stderr,
	"\n%s: Syntax error at line %u (%s).\n\n", opt.config, line, err);		
	exit (1);
}

/* return type of protocol of url saved in `str' */
static protocol_t
check_proto_t (const char *str)
{
    slassert (str != NULL);

    if (!strcasecmp (str, "http"))
	 return proto_http;
    else
    if (!strcasecmp(str, "ftp"))
	 return proto_ftp;
    else
    if (!strcasecmp(str, "file"))
	 return proto_file;
     
    slassert (NULL);
    return 0; /* never here */
}

	
static void
parse_config_mirror (char *cfgline, unsigned line)
{
	extern repositories *REPOS;
	extern unsigned N_REPOS;
    
	const char regex[] =
	"^repository[= \t]+" /* keyword */
	"([a-z0-9_\\-]{1,255})?[= \t]*" /* name for extra mirror */
	"(file|http|ftp)\\:+\\/+" /* mirror protocol */
	"([a-z0-9\\.\\-]+)" /* hostname or local mirror base path */
    "\\:?([0-9]+)?/*"   /* exra port to connect */
    "(.*[a-z0-9])?[\\/ \t]*$"; /* rest of string, normally mirror path */
	
	regex_t preg;
	regmatch_t matches[7];
	
	char *name, *protocol, *port, *hostname, *path;
	unsigned i = N_REPOS;

	xregcomp (&preg, regex, REG_EXTENDED|REG_ICASE);

	if (regexec (&preg, cfgline, 6, matches, 0))
	{
		cfg_syntax_error (cfgline, line);
	}
	
	name     = strregdup (cfgline, matches[1], 0);
	protocol = strregdup (cfgline, matches[2], 0);
	hostname = strregdup (cfgline, matches[3], 0);
    port     = strregdup (cfgline, matches[4], 0);
	path     = strregdup (cfgline, matches[5], 0);

    N_REPOS++;
	REPOS = xrealloc (REPOS, N_REPOS * sizeof (repositories));

	REPOS[i].name = (name == NULL) ? xstrdup ("slackware") : name;
    REPOS[i].port = (port) ? atoi (port) : 0x00;
    REPOS[i].hostname  = hostname;
	REPOS[i].path      = (path == NULL) ? xstrdup ("/") : path;
	REPOS[i].proto_t   = check_proto_t (protocol);
	REPOS[i].SLACKWARE = (bool) !(name);

	free (port);
    free (protocol);
	regfree (&preg);
	
	return;
}

static void
parse_config_blacklist (char *cfgline, unsigned line)
{
	extern options_t opt;
	char badreg[BUFFSIZE0];
	int rval;
	
	const char delim[] = "=, \t";
	char *ptr = cfgline + strlen ("blacklist");
	char *tok = strtok (ptr, delim);
	unsigned i;
	
	while (tok)
	{
		i = opt.nblacklisted++;

		opt.blacklisted = xrealloc (opt.blacklisted, opt.nblacklisted * sizeof (regex_t));

		if ((rval = regcomp (&opt.blacklisted[i], tok, REG_EXTENDED|REG_NOSUB)))
		{
			snprintf (badreg, BUFFSIZE, "regex `%s`: ", tok);
			regerror (rval, &opt.blacklisted[i], badreg + strlen (badreg), BUFFSIZE - strlen (badreg));
			cfg_syntax_error (badreg, line);
		}

		tok = strtok (NULL, delim);
	}
	return;
}

	
static char *
parse_config_value (char *cfgline, unsigned line)
{
	static char val[WORDSIZE0];
	char *ptr;
	const char regex[] = "[a-z0-9]+[= \t]+(.*)[ \t]*$";
	regex_t preg;
	regmatch_t matches[3];

	xregcomp (&preg, regex, REG_EXTENDED);

	if (regexec (&preg, cfgline, 2, matches, 0))
	{
		cfg_syntax_error (cfgline, line);
	}

	if (!(ptr = strregdup (cfgline, matches[1], 0))
	 || strlen (ptr) > WORDSIZE)
	{
		cfg_syntax_error (cfgline, line);
	}

	regfree (&preg);
	strcpy (val, ptr);
	free (ptr);
	return (val);
}
	

void
parse_config (void)
{
	extern repositories *REPOS;
	extern unsigned N_REPOS;
	extern options_t opt;
	
	const char comment[] = "!#\n";
	char buffer[HUGE0], *ptr, *tmp;
	const char *cfg = opt.config;
	FILE *fd = fopen (cfg, "r");
	int l, line = 0;

	REPOS   = NULL;
	N_REPOS = 0x00;
	opt.blacklisted  = NULL;
	opt.nblacklisted = 0x00;
	
	if (!file_exist (cfg, NULL, true) || !fd)
	{
		fprintf (stderr, "\n%s: %s\n\n", cfg, (!fd) ? strerror (errno) : "Not regular file");
		if (fd)
		 fclose (fd);
		exit (1);
	}

	while (fgets (buffer, HUGE, fd))
	{
		line++;
		ptr = buffer;

		while (isblank (*ptr))
                    ptr++;
		
		if (*ptr == 0x00 || strchr (comment, *ptr))
                    continue;

		l = strlen (ptr);
		if (--l > 0 && ptr[l] == '\n')
		 ptr[l] = 0x00;

		if (!strncasecmp (ptr, "repository", 10))
		{
			parse_config_mirror (ptr, line);
		}
		else
		if (!strncasecmp (ptr, "timeout", 7))
		{
			opt.TIMEOUT = atoi (parse_config_value (ptr, line));
		}
		else
		if (!strncasecmp (ptr, "blacklist", 9))
		{
			parse_config_blacklist (ptr, line);
		}
                else
                if (!strncasecmp (ptr, "cache", 5))
                {
                    opt.cache = xstrdup (parse_config_value (ptr, line));
                }
		else
                if (!strncasecmp (ptr, "upgrade_replacing_official", 26))
                {
                    tmp = parse_config_value (ptr, line);
                    if (!strcasecmp (tmp, "no"))
                    {
                        opt.upgrade_replacing_official = false;
                    }
                    else
                    if (strcasecmp (tmp, "yes"))
                    {
                        cfg_syntax_error (ptr, line);
                    }
                }
		else
                if (!strncasecmp (ptr, "wget", 4))
                {
                    tmp = parse_config_value (ptr, line);
                    if (!strcasecmp (tmp, "yes"))
                    {
                        opt.wget = true;
                    }
                    else
                    if (strcasecmp (tmp, "no"))
                    {
                        cfg_syntax_error (ptr, line);
                    }
                }
		else
                if (!strncasecmp (ptr, "slackware64", 11))
                {
                    tmp = parse_config_value (ptr, line);
                    if (!strcasecmp (tmp, "yes"))
                    {
                        opt.slackware64 = true;
                    }
                    else
                    if (strcasecmp (tmp, "no"))
                    {
                        cfg_syntax_error (ptr, line);
                    }
                }
		else
		{
			cfg_syntax_error (ptr, line);
		}
        }

	mirror_check ();
	mirror_fix_order ();
	
	return ;
}
/* +=========================================+
 * | Function to parse config file end
 * +=========================================+
 */

static void
tooopt (void)
{
	fprintf (stderr, "Too options. See help.\n");
	exit (1);
}

int
parse_options (int argc, char **argv)
{
    char c;

    if (argc < 2)
	 usage(argv[0]);

    memset (&p_fold, 0, sizeof (pkg_fold));
    memset (&opt, 0, sizeof (options_t));
    opt.check_dep        = true;
    opt.resolve_dep      = true;
	opt.warn             = true;
	opt.blacklist        = true;
	opt.hash             = true;
	opt.config           = xstrdup (CONFIGFILE);
    opt.upgrade_replacing_official = true;

    /* Set default cache if nothing specified in config file */
    if (opt.cache == NULL) {
        opt.cache = xstrdup (DATADIR);
    }
    opt.dest = xstrdup(opt.cache);

	while ((c = getopt(argc, argv, "5" "B:D::IL::O::PRSU::VX::" "b:c:d::efg:hl::mnpqr::s::uvw:xt:")) != -1) {
	
	switch (c) {
	
	case '5':
		opt.hash = false;
		break;
	case 'B':		/* build package from sources */
	    if (getuid ())
         _error (1, "\nYou must be root to build package sources.\n\n");
        opt.buildsrc = true;
	    opt.package = xstrdup(optarg);
	    opt.enabled++;
	    break;
	case 'D':		/* check for missing shared libraries */
	    opt.packager_dep = true;
	    opt.package      = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.enabled++;
	    p_fold.req       = (opt.check_dep) ? true : false;
	    p_fold.suggest   = (opt.check_dep) ? true : false;
	    p_fold.conflict  = true;
	    break;
	case 'I':
	    opt.skip_status = true;
	    break;
	case 'L':
	    opt.nslack_installed = true;
	    opt.package          = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.enabled++;
	    break;
	case 'O':
	    opt.obsolete = true;
	    opt.package  = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.enabled++;
	    break;
	case 'P':
	    opt.purge_all = true;
	    opt.enabled++;
	    break;
	case 'R':		/* show repositories stat */
	    opt.rstat     = true;
	    p_fold.size_c = true;
	    p_fold.size_u = true;
	    opt.enabled++;
	    break;
	case 'S':		/* skip missing dependencies check */
	    opt.check_dep = false;
	    opt.resolve_dep = false;
	    opt.notify_dep = false;
	    p_fold.req = false;
	    break;
	case 'U':		/* search new packages */
	    opt.upgrade     = true;
	    opt.package     = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.enabled++;
	    p_fold.req      = (opt.check_dep) ? true : false;
	    p_fold.suggest  = (opt.check_dep) ? true : false;
	    break;
	case 'V':
	    fprintf (stdout,
		    "+-----------------------------+\n"
	        "| Slackyd - Slacky Downloader |\n"
	        "+-----------------------------+\n"
            " Version: %s\n"
		    " Debug  : ", SLACKYD_VERSION);
        #if defined DEBUG
         printf ("yes\n");
        #else
         printf ("no\n");
        #endif
        fprintf (stdout,
		    " Mtrace : ");
		#if defined MTRACE
         printf ("yes\n");
        #else
         printf ("no\n");
        #endif
        fprintf (stdout,
		    " Profile: ");
		#if defined PROFILE
         printf ("yes\n");
        #else
         printf ("no\n");
        #endif
        fprintf (stdout, 
		    " Author : Giorgio \"Dani\" G.\n"
		    "          http://www.slacky.eu/~dani/\n"
		    " Please report bugs or suggests to <dani@slacky.it>.\n\n");
	    exit (EXIT_SUCCESS);
	    break;
    case 'X':
        opt.show_blacklisted = true;
        opt.package          = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.blacklist        = false;
	    opt.enabled++;
        break;
	

	case 'b':		/* get package build sources */
	    opt.getsrc  = true;
	    opt.package = xstrdup (optarg);
	    opt.enabled++;
	    break;
	case 'c':
	    free (opt.config);
            opt.config = xstrdup (optarg);
	    break;
	case 'd':		/* check for missing shared libraries */
	    opt.shared_dep  = true;
	    opt.package     = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.skip_status = true;
        opt.enabled++;
	    p_fold.req      = (opt.check_dep) ? true : false;
	    p_fold.suggest  = (opt.check_dep) ? true : false;
	    p_fold.conflict = true;
	    break;
	case 'e':
	    opt.use_regex = true;
	    break;
	case 'f':
	    opt.force = true;
	    break;
	case 'g':		/* get a package */
	    opt.get         = true;
	    opt.package     = xstrdup(optarg);
	    opt.enabled++;
	    p_fold.req      = (opt.check_dep) ? true : false;
	    p_fold.suggest  = (opt.check_dep) ? true : false;
	    p_fold.conflict = true;
	    break;
	case 'h':
		usage (argv[0]);
		break;
	case 'l':
	    opt.installed = true;
	   	opt.package   = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.enabled++;
	    break;
	case 'm':
	    opt.case_insensitive = true;
	    break;
	case 'n':		/* not ask for missing dependencies download, show only a notify */
	    if (!opt.check_dep)	/* dependencies check disabled */
		 usage(argv[0]);
	    opt.resolve_dep = false;
	    opt.notify_dep  = true;
	    p_fold.req      = true;
	    break;
	case 'p':
	    opt.purge = true;
	    opt.enabled++;
	    break;
	case 'q':
	    opt.warn = false;
	    break;
	case 'r':		/* show replaceable packages */
	    opt.replaceable = true;
        opt.skip_status = true;
	    opt.package     = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.enabled++;
	    break;
	case 's':		/* search package in repository */
	    opt.search        = true;
	    opt.package       = (optind != argc && argv[optind][0] != '-') ? xstrdup(argv[optind]) : NULL;
	    opt.print_status  = true;
	    opt.enabled++;
        break;
	case 't':		/* use a different path to download packages */
	    opt.dest          = xstrdup(optarg);
	    break;
	case 'u':		/* update file list */
	    opt.update = true;
	    opt.enabled++;
	    break;
	case 'v':
	    opt.verbose = true;
	    break;
	case 'w':		/* show info */
	    opt.view = true;
	    opt.package       = xstrdup(optarg);
	    opt.print_status  = true;
	    opt.enabled++;
	    p_fold.size_c     = true;
	    p_fold.size_u     = true;
	    p_fold.req        = true;
	    p_fold.conflict   = true;
	    p_fold.suggest    = true;
	    p_fold.desc       = true;
	    break;
    case 'x':
        opt.blacklist = false;
        break;
	
	
	case '?':
		exit (EXIT_FAILURE);
	default:		/* error */
	    usage(argv[0]);
	    break;

	}
    }

    if (opt.enabled > 1)
     tooopt ();
	    
    if (opt.verbose) {
        p_fold.size_c = true;
	    p_fold.size_u = true;
    }
	    
    if (opt.enabled < 1)
	 _error (1, "Nothing to do.\n");

	if (!opt.use_regex && opt.package && !isalnum (opt.package[0]))
	 _error (3, "Invalid argument \"", opt.package, "\".\n"
	            "Use -e switch to enable regex.\n");
	 
    return EXIT_SUCCESS;
}




/*--------------- slackyd function to manage types start ---------------*/
void
dlist_add (dlist **list, char *s)
{
    dlist *current = *list;

    if (current == NULL)
    {
        (*list)       = xmalloc (sizeof (dlist));
        (*list)->s    = s;
        (*list)->next = NULL;
    }
    else
    {
        while (current->next)
         current = current->next ;

        current->next = xmalloc (sizeof (dlist));
        current       = current->next;
        current->s    = s;
        current->next = NULL;
    }
}

void
dlist_free (dlist **list)
{
    dlist *current = *list, *prev;
    
    if (!list || *list == NULL)
     return;

    do {
        free (current->s);
        prev = current;
        current = current->next;
        free (prev);
    } while (current);

    *list = NULL;
}

unsigned
dlist_count (dlist *list)
{
    unsigned i = 0;
    dlist *current = list;

    while (current) {
        i++;
        current = current->next;
    }
    return i;
}

bool
dlist_check (dlist *list, const char *s)
{
    dlist *current = list;

    while (current) {
        if (strcmp (current->s, s) == 0)
         return 1;
        current = current->next;
    }
    return 0;
}

void
dlist_print (dlist *list, const char *delim1, const char *delim2)
{
    dlist *current = list;

    while (current) {
        fprintf (stdout, "%s%s%s", (delim1) ? delim1 : "", current->s, (delim2) ? delim2 : "");
        current = current->next;
    }
    return;
}

void
pkgl_add (pkg_l **pkglist, pkg_t *pkg)
{
    pkg_l *current = *pkglist;

    if (pkg == NULL)
     return;

    if (current == NULL)
    {
        (*pkglist)       = xmalloc (sizeof (pkg_l));
        (*pkglist)->p    = pkg;
        (*pkglist)->next = NULL;
    }
    else
    {
        while (current->next) current = current->next ;

        current->next = xmalloc (sizeof (pkg_l));
        current       = current->next;
        current->p    = pkg;
        current->next = NULL;
    }

    return ;
}

void
pkgl_free (pkg_l **pkglist)
{
    pkg_l *current = *pkglist, *prev;
    
    if (*pkglist == NULL)
     return;

    do {
        pkg_t_free (&current->p);
        prev = current;
        current = current->next;
        free (prev);
    } while (current);

    *pkglist = NULL;
    return;
}

unsigned
pkgl_count (pkg_l *pkglist)
{
    pkg_l *current = pkglist;
    unsigned i = 0;

    while (current) {
        current = current->next;
        i++;
    }
    return i;
}


void
pkgl_join (pkg_l **head, pkg_l *end)
{
    pkg_l *current = *head;

    if (*head == NULL)
	{
        *head = end;
        return;
    }

    while (current->next)
     current = current->next;
    current->next = end;
}

void
pkgl_print (pkg_l *pkglist, const char *delim1, const char *delim2)
{
    pkg_l *current = pkglist;

    while (current) {
        fprintf (stdout, "%s%s%s", (delim1) ? delim1 : "", current->p->name, (delim2) ? delim2 : "");
        current = current->next;
    }
    return;
}

bool
pkgl_check (const char *pkgname, pkg_l *pkglist, int flag)
{
    pkg_l *current = pkglist;
    int rval;
    char *ext1, *ext2;

    rval = -1;

    switch (flag)
    {
        case MATCH_EXACTLY_NAME:
            while (current && rval != 0)
            {
                rval = strcmp (pkgname, current->p->pstruct.name);
                current = current->next;
            }
            break;

        case MATCH_EXACTLY_PACKAGE:
            while (current && rval != 0)
            {
                if ((ext1 = strcasestr (pkgname, ".txz\0"))
                 || (ext1 = strcasestr (pkgname, ".tgz\0")))
                {
                    *ext1 = 0x00;
                }

                if ((ext2 = strcasestr (current->p->name, ".txz\0"))
                 || (ext2 = strcasestr (current->p->name, ".tgz\0")))
                {
                    *ext2 = 0x00;
                }

                rval = strcmp (pkgname, current->p->name);

                if (ext1) {
                    *ext1 = '.';
                }
                if (ext2) {
                    *ext2 = '.';
                }

                current = current->next;
            }
            break;

        default:
            slassert (NULL);
            break;
    }

    return (rval == 0);
}

pkg_t **
pkgl2pkgt (pkg_l *pkglist, unsigned *n)
{
    unsigned i = pkgl_count (pkglist), j = 0;
    pkg_l *current = pkglist, *prev;
    pkg_t **packages = NULL;

    if (i < 1) {
        *n = 0;
        return NULL;
    }
     
    packages = xmalloc (i * sizeof (pkg_t *));

    while (current)
	{
        packages[j++] = current->p;
        prev    = current;
        current = current->next;
        free (prev);
    }
    *n = j;
    return packages;
}

/* copy a dep_t array structure `src' to a dep_t array `dest'.
 * Array is maked of `n' structure.
 */ 
static void
cp_dep_t (dep_t *src, dep_t **dest, int n)
{
    int i, memsz = n * sizeof (dep_t);
    
    if (n <= 0) {
        *dest = NULL;
        return;
    }

    *dest = (dep_t *) xmalloc (memsz);
    memset (*dest, 0, memsz);

    for (i = 0; i < n; )
	{
		add_dep (src[i].name, src[i].op, src[i].version, src[i].type, dest, &i);
		(*dest)[i - 1].OR_next = src[i - 1].OR_next;
		(*dest)[i - 1].missing = src[i - 1].missing;
	}

    return;
}

/* free a dep_t array `dep' on `n' structure
 * and set pointer to NULL
 */
static void
free_dep_t (dep_t *dep[], int n)
{
    int i;

    if (n <= 0)
     return;
    else
     for (i = n - 1; i >= 0; i--) {
         free ((*dep)[i].name);
         free ((*dep)[i].version);
     }

    free (*dep);
    *dep = NULL;
     
     return;
 }


bool
pkg_t_check (const char *name, pkg_t *packages[], unsigned npackages, int flag)
{
    int rval;
    char *ext1, *ext2;
    unsigned i;

    rval = -1;
    
    if (packages)
    switch (flag)
    {
        case MATCH_EXACTLY_NAME:
            for (i = 0; rval != 0 && i < npackages; i++)
            {
                rval = strcmp (name, packages[i]->pstruct.name);
            }
            break;
            
        case MATCH_EXACTLY_PACKAGE:
            for (i = 0; rval != 0 && i < npackages; i++)
            {
                if ((ext1 = strcasestr (name, ".txz\0"))
                 || (ext1 = strcasestr (name, ".tgz\0")))
                {
                    *ext1 = 0x00;
                }

                if ((ext2 = strcasestr (packages[i]->name, ".txz\0"))
                 || (ext2 = strcasestr (packages[i]->name, ".tgz\0")))
                {
                    *ext2 = 0x00;
                }
                
                rval = strcmp (name, packages[i]->name);

                if (ext1) {
                    *ext1 = '.';
                }
                if (ext2) {
                    *ext2 = '.';
                }
            }
            break;
            
        default:
            slassert (NULL);
            break;
    }

    return (rval == 0);
}

/* copy pkg_t `src' to `dest' using policy setted by external `p_fold'. */
pkg_t *
pkg_t_dup (pkg_t *src)
{
    pkg_t *pkg = xmalloc (sizeof (pkg_t));
    
    memset (pkg, 0, sizeof (pkg_t));

	pkg->name = xstrdup(src->name);

    strncpy (pkg->pstruct.name,    src->pstruct.name,    NAMESIZE);
    strncpy (pkg->pstruct.version, src->pstruct.version, VERSIONSIZE);
    strncpy (pkg->pstruct.arch,    src->pstruct.arch,    ARCHSIZE);
    strncpy (pkg->pstruct.build,   src->pstruct.build,   BUILDSIZE);

    pkg->location = xstrdup (src->location);

	pkg->blacklisted = src->blacklisted;
	

    if (p_fold.size_c)
	 pkg->size_c = src->size_c;
    

    if (p_fold.size_u)
	 pkg->size_u = src->size_u;

    if (p_fold.req && src->nrequired > 0)
     cp_dep_t (src->required, &pkg->required, src->nrequired);
    else
     pkg->required = NULL;
    
    pkg->nrequired = src->nrequired;

    if (p_fold.conflict && src->nconflicts > 0)
     cp_dep_t (src->conflicts, &pkg->conflicts, src->nconflicts);
    else
     pkg->conflicts = NULL;

    pkg->nconflicts = src->nconflicts;
    
    
    if (p_fold.suggest && src->nsuggests > 0)
     cp_dep_t (src->suggests, &pkg->suggests, src->nsuggests);
    else
     pkg->suggests = NULL;

    pkg->nsuggests = src->nsuggests;
    

    if (p_fold.desc)
	 pkg->desc = xstrdup(src->desc);
    
    
    pkg->N_REPO = src->N_REPO;
    pkg->branch = src->branch;

    pkg->status    = src->status;
    pkg->installed = xstrdup (src->installed);
    
    return pkg;
}

void
pkg_t_add (pkg_t **packages[], unsigned *npackages, pkg_t *pnew)
{
    unsigned n = *npackages;
    (*packages)    = (pkg_t **) xrealloc ((*packages), (n + 1) * sizeof (pkg_t *));
    (*packages)[n] = pkg_t_dup (pnew);
    ++*npackages;
}


/* remove package `memb' from a pkg_t list `packages'.
 * `npackages' will be decremented.
 */
void
pkg_t_rm (pkg_t **packages[], unsigned *npackages, unsigned memb)
{
    unsigned i = memb;

    /* check for end of list */
    if (i == *npackages) {
        pkg_t_free (&(*packages)[i]);
        --*npackages;
        return;
    }

    pkg_t_free (&(*packages)[i]);
    while (i < *npackages - 1) {
    	(*packages)[i] = (*packages)[i + 1];
        i++;
    }

    --*npackages;

    if (*npackages == 0) {
        free (*packages);
        *packages = NULL;
    }

    return;
}

/* free one pkg_t package data */
void
pkg_t_free (pkg_t **addr)
{
    if (addr == NULL)
	 return;

    free ((*addr)->name);
    
    free ((*addr)->location);

    if (p_fold.req && (*addr)->nrequired > 0)
     free_dep_t (&(*addr)->required, (*addr)->nrequired);

    if (p_fold.conflict)
     free_dep_t (&(*addr)->conflicts, (*addr)->nconflicts);
    
    if (p_fold.suggest)
     free_dep_t (&(*addr)->suggests, (*addr)->nsuggests);
    
    if (p_fold.desc)
	 free ((*addr)->desc);
	
    if ((*addr)->status >= 0)
     free ((*addr)->installed);

    free (*addr);
    *addr = NULL;
    
    return;
}

/* free all `elements' of pkg_t `addr' packages data */
void
pkg_t_free_all (pkg_t **addr[], unsigned elements)
{
    int i;

    if (!addr || !elements)
     return;

    for (i = elements - 1; i >= 0; i--)
	{
	    pkg_t_free(&((*addr)[i]));
    }

    free (*addr);
    *addr = NULL;
    
    return;
}
   

void
init_net_t (net_t *netpolicy, protocol_t p, unsigned port)
{
    memset (netpolicy, 0, sizeof (net_t));
    netpolicy->timeout = opt.TIMEOUT;
    netpolicy->sd      = -1;
    netpolicy->pasvsd  = -1;
    netpolicy->fddest  = NULL;

    if (port != 0) {
        netpolicy->port = port;
    }
    else {
        switch (p) {
            case proto_http: netpolicy->port = 80; break;
            case proto_ftp : netpolicy->port = 21; break;
            case proto_file:                       break;
            default  : slassert (NULL);            break;
        }
    }

    return;
}

int
shutdown_net_t (net_t *netpolicy, int rval, const char *msg)
{
    char srcpart[BUFFSIZE0];
    
    if (netpolicy->ftpquit)
     send (netpolicy->sd, "QUIT\r\n", 6, 0);

    if (netpolicy->sd >= 0)
     close (netpolicy->sd);

    if (netpolicy->pasvsd >= 0)
     close (netpolicy->pasvsd);

    if (netpolicy->fddest)
     fclose (netpolicy->fddest);

    if (netpolicy->savepart &&
        !strcmp (netpolicy->destpath + strlen (netpolicy->destpath) - 5, ".part"))
    {
        strncpy (srcpart, netpolicy->destpath, BUFFSIZE);
        *strrchr (netpolicy->destpath, '.') = 0x00;
        
        if ((remove (netpolicy->destpath) < 0 && errno != ENOENT)
          || rename (srcpart, netpolicy->destpath) < 0)
        {
            rval = -1;
            msg  = netpolicy->destpath;
        }
    } 
        
    if (msg || rval < 0)
    {
        clrline (stdout, strlen (netpolicy->msg) + 30);
        fprintf (stdout, "%s [%s", netpolicy->msg, (msg) ? msg : "");
        if (rval < 0 && errno)
         fprintf (stdout, "%s%s", (msg) ? ": " : "", strerror (errno));
        fprintf (stdout, "]\n");
    }

    return rval;
}

int
is_installed (const char *name, int flags, unsigned start)
{
    unsigned n = start;
    regex_t preg;
    int cflags = REG_EXTENDED | REG_NOSUB;

    slassert (name != NULL);

    switch (flags) {
        case MATCH_ALL_NAME:
            while (n < nginst)
			 if (xstrstr (ginst[n].name, name))
              return n;
             else
              n++;
            break;

        case MATCH_EXACTLY_NAME:        
            while (n < nginst)
             if (xstrcmp (name, ginst[n].pstruct.name) == 0)
              return n;
             else
              n++;
            break;

        case MATCH_EXACTLY_PACKAGE:        
            while (n < nginst)
             if (xstrcmp (name, ginst[n].name) == 0)
              return n;
             else
              n++;
            break;

        case MATCH_USING_REGEX:
            if (opt.case_insensitive)
             cflags |= REG_ICASE;
            xregcomp (&preg, name, cflags);
            while (n < nginst)
             if (regexec (&preg, ginst[n].name, 0, NULL, 0) == 0) {
                 regfree (&preg);
                 return n;
             }
             else
              n++;
            regfree (&preg);
            break;
            
        default:
            slassert (NULL);
            break;
    }
     
    return PACKAGE_STATUS_NOT_INSTALLED;
}



/* check for package operator and return opportune macro.
 * we can use isop() function instead of this (see search.c) , but this ensure
 * more security because isop() can parse also dependency name or version.
 * In this case is hard understand what token we're parsing :)
 */
static char
op_type (const char *op)
{
    if (!op || op[0] == 0x00)
     return VERSION_ALL;
    else
    if (!strcmp (op, "<"))
     return VERSION_MINOR;
    else
    if (!strcmp (op, "<="))
     return VERSION_MINOR_OR_EQUAL;
    else
    if (!strcmp (op, "=") || !strcmp (op, "=="))
     return VERSION_EQUAL;
    else
    if (!strcmp (op, ">"))
     return VERSION_MAJOR;
    else
    if (!strcmp (op, ">="))
     return VERSION_MAJOR_OR_EQUAL;
    else
     slassert (NULL);

    return 0;
}
    
/* add a dep "name >=|=|<= version" to a dep_t list `dest' of `n' elements.
 * If op and version is NULL will be add just name.
 */
void
add_dep (const char *name, const char *op, const char *version, unsigned char type, dep_t **dest, int *n)
{
    int i = *n;
    char *ptr = NULL;

    *dest = xrealloc (*dest, (i + 1) * sizeof (dep_t));
    memset (&(*dest)[i], 0 , sizeof (dep_t));

    slassert (name != NULL);
    (*dest)[i].name = xstrdup (name);
    

    memset (&(*dest)[i].op, 0, sizeof ((*dest)[i].op));
    /* Before check for NULL operator, after test first character.
     * We consider `op' NULL and `op[0]' NULL equal :)
     * This for skip program crash when NULL is passed as `op'.
     */
    if (op && op[0])
     strncpy ((*dest)[i].op, op, sizeof ((*dest)[i].op) - 1);
    
    (*dest)[i].op_t = op_type (op);
   
    (*dest)[i].version = NULL;
	if (version)
	{
        if ((ptr = strchr (version, '-')))
         *ptr = 0x00; /* sometimes version folder containe also arch and build */
        (*dest)[i].version = xstrdup (version);
        if (ptr)
         *ptr = '-';
    }
     
    (*dest)[i].type = type;

    ++*n;
    return;
}


void free_installed_t (installed_t **sp, unsigned n)
{

    if (!n)
     return;

    while (--n)
     free ((*sp)[n].name);
    
    free ((*sp)[0].name);
    free (*sp);
    *sp = NULL;
    
    return;
}
/*--------------- slackyd function manage types end ---------------*/




/* process directory where we search shared libraries */
void
process_lib_path (dlist **paths)
{
    FILE *fd;
    char *buffer = NULL, *ptr = NULL, *env = NULL;
    
    buffer = xmalloc (BUFFSIZE0 * sizeof (char));
    ptr = buffer; /* buffer can be moved; we use ptr for free memory */

    if (!(fd = fopen ("/etc/ld.so.conf", "r")))
	{
		printfw ("\nWarning:\nCannot open ld.so.conf: %s\n", strerror (errno));
		free (buffer);
	}

    dlist_add (paths, xstrdup ("/lib"));
    dlist_add (paths, xstrdup ("/usr/lib"));

    while (fgets(buffer, BUFFSIZE, fd))
	{
		if (buffer[0] == '\n')	/* void line ? skip ! :) */
		 continue;

		if (buffer[strlen(buffer) - 1] == '\n')
	     buffer[strlen(buffer) - 1] = 0x00;

		movestrlim (&buffer, " \t", 2);

		if (dlist_check (*paths, buffer) == 0)
		{
			dlist_add (paths, xstrdup (buffer));
		}
    }
	
    free (ptr);
    
    if (!(buffer = getenv ("LD_LIBRARY_PATH")))
	{
		fclose (fd);
		return ;
    }

    movestrlim (&buffer, ":", 0);

	while ((env = strsep (&buffer, ":")))
	{
		movestrlim (&env, ":", 0);

		if (dlist_check (*paths, env) == 0)
		{
			dlist_add (paths, env);
		}
    }

    fclose (fd);
    return ;
}


#define ISELF(header) \
		(header[EI_MAG0] == ELFMAG0 && \
		 header[EI_MAG1] == ELFMAG1 && \
		 header[EI_MAG2] == ELFMAG2 && \
		 header[EI_MAG3] == ELFMAG3)

/* check if `file' is a regular ELF file (executable or shared object) */
static bool
process_reg_elf(const char *file, FILE ** fd, ElfData * Elf)
{
    struct stat s_stat;

    if (stat(file, &s_stat) != 0 || !S_ISREG(s_stat.st_mode))
    {
        return true;
    }
    
    if (!(*fd = fopen (file, "rb")))
    {
        return true;
    }
    
    if (fread((unsigned char *) Elf->e_ident, 1, EI_NIDENT, *fd) != EI_NIDENT)
    {
        fclose (*fd);
        return true;
    }
    
    
    if (!ISELF(Elf->e_ident))
    {
        fclose (*fd);
	    return true;
    }
    
    return false;
}

/* read file header and check for ELF file */
static bool
process_elf_header(FILE * fd, ElfData * Elf)
{
    if (fseek(fd, 0, SEEK_SET))
    {
        return true;
    }

    switch (Elf->e_ident[EI_CLASS])
    {
        case ELFCLASSNONE:
	        printfv ("error: invalid elf class (0x%.2x).\n", Elf->e_ident[EI_CLASS]);
		    return true;
        break;
    
        case ELFCLASS32:
	        if (fread ((Elf32_Ehdr *) & Elf->Elf32_Header, sizeof (Elf32_Ehdr), 1, fd) == 1)
            {
                return false;
            }
		    break;
        
        case ELFCLASS64:
	        if (fread ((Elf64_Ehdr *) & Elf->Elf64_Header, sizeof (Elf64_Ehdr), 1, fd) == 1)
            {
                return false;
            }
	    break;
        
        default:
	        printfv ("error: unknow elf class (0x%.2x).\n", Elf->e_ident[EI_CLASS]);
	        return true;
	    break;
    }
    
    return true; /* :-m */
}

/* check for ELF executable or shared object */
static bool
process_elf_type(ElfData * Elf)
{
    bool rval = false;

    switch (Elf->e_ident[EI_CLASS])
    {
    case ELFCLASS32:
        rval = (Elf->Elf32_Header.e_type == ET_EXEC || Elf->Elf32_Header.e_type == ET_DYN);
		break;
    
    case ELFCLASS64:
		rval = (Elf->Elf64_Header.e_type == ET_EXEC || Elf->Elf64_Header.e_type == ET_DYN);
		break;
    
    default:
	    printfv ("unexpected error processing elf type.\n");
		break;
    }
    
    return (rval) ? 0 : 1;
}

/* process ELF section header */
static bool
process_elf_section_header(FILE * fd, ElfData * Elf)
{
    int i;
    unsigned SH_Size;

    switch (Elf->e_ident[EI_CLASS])
    {
        case ELFCLASS32:

            /* check for section header */
            if (Elf->Elf32_Header.e_shoff == 0)
            {
                printfv ("error: elf haven't a section header.\n");
                return true;
            }

            if (fseek(fd, Elf->Elf32_Header.e_shoff, SEEK_SET))
            {
                return true;
            }

            /* alloc memory for sections header */
            SH_Size = Elf->Elf32_Header.e_shnum * Elf->Elf32_Header.e_shentsize;
            Elf->Elf32_SectionHeader = (Elf32_Shdr *) xmalloc (SH_Size);

            for (i = 0; i < Elf->Elf32_Header.e_shnum; i++)
            {
                if (fread ((Elf32_Shdr *) & Elf->Elf32_SectionHeader[i], Elf->Elf32_Header.e_shentsize, 1, fd) != 1)
                {
                    return true;
                }
            }

            break;

        case ELFCLASS64:
            /* check for section header */
            if (Elf->Elf64_Header.e_shoff == 0)
            {
                printfv ("error: elf haven't a section header.\n");
                return true;
            }

            if (fseek(fd, Elf->Elf64_Header.e_shoff, SEEK_SET))
            {
                return true;
            }

            /* alloc memory for sections header */
            SH_Size = Elf->Elf64_Header.e_shnum * Elf->Elf64_Header.e_shentsize;
            Elf->Elf64_SectionHeader = (Elf64_Shdr *) xmalloc(SH_Size);

            for (i = 0; i < Elf->Elf64_Header.e_shnum; i++)
            {
                if (fread ((Elf64_Shdr *) & Elf->Elf64_SectionHeader[i], Elf->Elf64_Header.e_shentsize, 1, fd) != 1)
                {
                    return true;
                }
            }

            break;


        default:

            printfv ("unexpected error processing elf section header.\n");

            return true;

            break;
    }
    
    return false;
}

/* search and save ELF string table offset */
static bool
process_elf_strtab(ElfData * Elf)
{
    int i;

    switch (Elf->e_ident[EI_CLASS])
    {
        case ELFCLASS32:
            for (i = 0; i < Elf->Elf32_Header.e_shnum; i++)
            {
                if (Elf->Elf32_SectionHeader[i].sh_type == SHT_STRTAB)
                {
                    Elf->strtab_off = Elf->Elf32_SectionHeader[i].sh_offset;
                    return false;
                }
            }
            break;

        case ELFCLASS64:
            for (i = 0; i < Elf->Elf64_Header.e_shnum; i++)
            {
                if (Elf->Elf64_SectionHeader[i].sh_type == SHT_STRTAB)
                {
                    Elf->strtab_off = Elf->Elf64_SectionHeader[i].sh_offset;
                    return false;
                }
            }
            break;

        default:

            printfv ("unexpected error processing elf strtab offset.\n");

            return true;

            break;
    }
    
    return true;
}

/* find elf dynamic index */
static bool
process_elf_dyn_index(ElfData * Elf)
{
    int i;

    switch (Elf->e_ident[EI_CLASS])
    {
        case ELFCLASS32:
            for (i = 0; i < Elf->Elf32_Header.e_shnum; i++)
            {
                if (Elf->Elf32_SectionHeader[i].sh_type == SHT_DYNAMIC)
                {
                    Elf->dyn_index = i;
                    return false;
                }
            }
            break;

        case ELFCLASS64:
            for (i = 0; i < Elf->Elf64_Header.e_shnum; i++)
            {
                if (Elf->Elf64_SectionHeader[i].sh_type == SHT_DYNAMIC)
                {
                    Elf->dyn_index = i;
                    return false;
                }
            }
            break;

        default:

            printfv ("unexpected error processing elf dynamic index.\n");

            return true;

            break;
    }
    
    return true;
}


/* read and process ELF dynamic section */
static bool
process_elf_dynamic_section (FILE * fd, ElfData * Elf)
{
    unsigned i;
    unsigned short Dyn_Index = Elf->dyn_index;

    switch (Elf->e_ident[EI_CLASS])
    {
        case ELFCLASS32:
            /* dynamic section sanity check */
            if (Elf->Elf32_SectionHeader[Dyn_Index].sh_entsize == 0)
            {
                return true;
            }

            /* alloc memory for dynamic section entries */
            Elf->dyn_entries =
                Elf->Elf32_SectionHeader[Dyn_Index].sh_size /
                Elf->Elf32_SectionHeader[Dyn_Index].sh_entsize;

            Elf->Elf32_DynamicSection = (Elf32_Dyn *)
                xmalloc (Elf->dyn_entries * sizeof (Elf32_Dyn));

            /* read dynamic entries */
            if (fseek (fd, Elf->Elf32_SectionHeader[Dyn_Index].sh_offset, SEEK_SET))
            {
                return true;
            }

            for (i = 0; i < Elf->dyn_entries; i++)
            {
                if (fread ((Elf32_Dyn *) & Elf->Elf32_DynamicSection[i], Elf->Elf32_SectionHeader[Dyn_Index].sh_entsize, 1, fd) != 1)
                {
                    return true;
                }

                if (Elf->Elf32_DynamicSection[i].d_tag == DT_NULL)
                {
                    Elf->dyn_entries = i + 1;	/* we include DT_NULL */
                    break;
                }
            }

            break;
	
	
	    case ELFCLASS64:
            /* dynamic section sanity check */
            if (Elf->Elf64_SectionHeader[Dyn_Index].sh_entsize == 0)
            {
                return true;
            }

            /* alloc memory for dynamic section entries */
            Elf->dyn_entries =
                Elf->Elf64_SectionHeader[Dyn_Index].sh_size /
                Elf->Elf64_SectionHeader[Dyn_Index].sh_entsize;

            Elf->Elf64_DynamicSection = (Elf64_Dyn *)
                xmalloc (Elf->dyn_entries * sizeof (Elf64_Dyn));

            /* read dynamic entries */
            if (fseek (fd, Elf->Elf64_SectionHeader[Dyn_Index].sh_offset, SEEK_SET))
            {
                return true;
            }

            for (i = 0; i < Elf->dyn_entries; i++)
            {
                if (fread ((Elf64_Dyn *) & Elf->Elf64_DynamicSection[i], Elf->Elf64_SectionHeader[Dyn_Index].sh_entsize, 1, fd) != 1)
                {
                    return true;
                }

                if (Elf->Elf64_DynamicSection[i].d_tag == DT_NULL)
                {
                    Elf->dyn_entries = i + 1;	/* we include DT_NULL */
                    break;
                }
            }

            break;
    

        default:
            printfv ("unexpected error processing elf dynamic section.\n");

            return true;

            break;
    }

    return false;
}

/* get RPATH (deprecated :-?) */
static char *
process_elf_rpath (FILE *fd, ElfData *Elf)
{
    char rpath[BUFFSIZE0] = { 0 };
    unsigned i, offset;

    switch (Elf->e_ident[EI_CLASS])
    {
        case ELFCLASS32:
            for (i = 0; i < Elf->dyn_entries; i++)
            {
                if (Elf->Elf32_DynamicSection[i].d_tag == DT_RPATH)
                {
                    offset = Elf->strtab_off + Elf->Elf32_DynamicSection[i].d_un.d_val;

                    if (fseek(fd, offset, SEEK_SET))
                    {
                        return NULL;
                    }

                    return (fgets(rpath, BUFFSIZE, fd)) ? xstrdup(rpath) : NULL;
                }
            }

            break;
	
        case ELFCLASS64:
            for (i = 0; i < Elf->dyn_entries; i++)
            {
                if (Elf->Elf64_DynamicSection[i].d_tag == DT_RPATH)
                {
                    offset = Elf->strtab_off + Elf->Elf64_DynamicSection[i].d_un.d_val;

                    if (fseek(fd, offset, SEEK_SET))
                    {
                        return NULL;
                    }

                    return (fgets(rpath, BUFFSIZE, fd)) ? xstrdup(rpath) : NULL;
                }
            }
            break;


            default:
                printfv ("\nUnexpected error processing elf rpath.\n");
                break;
    }
    
    return NULL;
}


/* search `needed' library in `path' directories */
static bool
search_needed(char *needed, dlist *lpath)
{
    dlist *current = lpath;
    char buffer[BUFFSIZE0];
    struct stat s_stat;

    while (current)
    {
        snprintf (buffer, BUFFSIZE, "%s/%s", current->s, needed);

        if (!lstat(buffer, &s_stat))
        {
            return false;
        }

        current = current->next;
	}

    return true;
}

/* if dynamic section entry is a DT_NEEDED return offset of a string in
 * the string table, otherwise return 0
 */
static unsigned
get_needed_off (ElfData Elf, unsigned memb)
{

    unsigned offset = 0;

    switch (Elf.e_ident[EI_CLASS])
    {
        case ELFCLASS32:
            if (Elf.Elf32_DynamicSection[memb].d_tag == DT_NEEDED)
            {
                offset = Elf.strtab_off + Elf.Elf32_DynamicSection[memb].d_un.d_val;
            }
            break;

        case ELFCLASS64:
            if (Elf.Elf64_DynamicSection[memb].d_tag == DT_NEEDED)
            {
                offset = Elf.strtab_off + Elf.Elf64_DynamicSection[memb].d_un.d_val;
            }
            break;
	
	    default:
            slassert (NULL);
            break;
	}
	
    return offset;
}

/* return a string from the string table, started from offset and NULL terminated */
static char *
get_needed (FILE * fd, unsigned long offset)
{
    static char buffer[WORDSIZE0];

    if (fseek(fd, offset, SEEK_SET))
    {
        return NULL;
    }

    memset (buffer, WORDSIZE0, 0);

    return fgets (buffer, WORDSIZE, fd);
}

/* check if file `file' is present on packages `tgz'
 * Sometimes shared libraries are in the same package !
 */
static bool
file_in_tgz (const char *file, const char *tgz)
{
    FILE *fd;
    char *dfile = NULL;
    char pfile[BUFFSIZE0];

    snprintf (pfile, BUFFSIZE, "%s/%s", PKGDIR, tgz);

    if (!(fd = fopen (pfile, "r")))
	{
		printfw ("\nWarning: cannot open %s: %s\n", tgz, strerror (errno));
		return false;
    }

    fdload (&dfile, fd, get_file_size(fd));
    fclose (fd);
    
    if (dfile == NULL) {
        fprintf (stderr, "Error, %s seem to be void.\n", pfile);
        return true;
    }


    if (strstr (dfile, file)) {
		free (dfile);
		return false;
    }

    free (dfile);
    return true;
}

/* check for libraries already in list */
static int
dup_needed (libneed_t *mlibs, unsigned n_mlibs, const char *entry)
{
    unsigned i;

    for (i = 0; i < n_mlibs; i++)
	 if (!strcmp (mlibs[i].needed, entry))
	  return (int) i;

    return -1;
}


#define cleanup(Elf_Data, err) {          \
	free (Elf_Data.Elf32_SectionHeader);  \
	free (Elf_Data.Elf64_SectionHeader);  \
	free (Elf_Data.Elf32_DynamicSection); \
	free (Elf_Data.Elf64_DynamicSection); \
	free (Elf_Data.rpath);   \
	if (err) {               \
		return EXIT_FAILURE; \
	}						 \
	}

/* check shared libraries of file `file' of package `tgz' */
int
check_elf_libs (dlist *libpath, char *file, libneed_t *mlibs[], unsigned *n_mlibs, char *tgz)
{
    dlist *rlibpath = libpath; /* library path with added executable rpath */
    FILE *fd;
    ElfData Elf;
    char *needed = NULL;
    int i, t_index;
    unsigned off_needed, m_index;
    
    memset (&Elf, 0, sizeof (Elf));

    if  (process_reg_elf             (file, &fd, &Elf))
     cleanup (Elf, 1);
    if  (process_elf_header          (fd, &Elf)
	  || process_elf_type            (&Elf)
	  || process_elf_section_header  (fd, &Elf)
	  || process_elf_strtab          (&Elf)
	  || process_elf_dyn_index       (&Elf)
	  || process_elf_dynamic_section (fd, &Elf)) {
	      fclose (fd);
	      cleanup(Elf, 1);
      }

    /* First path is reserved to RPATH string.
     * If executable has it, add to library path begin.
     */
     if ((Elf.rpath = process_elf_rpath (fd, &Elf)) != NULL)
     {
         rlibpath       = malloc (sizeof (dlist));
         rlibpath->s    = Elf.rpath;
         rlibpath->next = libpath;
     }

    /* check for needed libraries */
    for (i = 0; (unsigned) i < Elf.dyn_entries; i++) {

    if ( (off_needed = get_needed_off (Elf, i)) == 0  /* entry isn't a DT_NEEDED or offset not obtained */
       ||(needed = get_needed (fd, off_needed)) == 0  /* string of needed object not read               */
	   || search_needed (needed, rlibpath)      == 0  /* library found in the libraries path of system  */
	   || file_in_tgz (needed, tgz)             == 0) /* library is in the same package that require it */
	 continue;

    /* verify if missing object is already in list.
     * In this case we don't add a new entry in libneed_t array, but simply
     * add package name and object name that require library to an existant
     * array index !
     */
    t_index = dup_needed (*mlibs, *n_mlibs, needed);
    m_index = (t_index < 0) ? *n_mlibs : (unsigned) t_index;

	if (t_index < 0) {
	*mlibs = (libneed_t *)
	    xrealloc (*mlibs, (*n_mlibs + 1) * sizeof (libneed_t));
    memset (&(*mlibs)[*n_mlibs], 0, sizeof (libneed_t));
    }
		
    /* save missing libraries */
    if (t_index < 0)
    {
        snprintf ((*mlibs)[m_index].needed,  NEEDSIZE, needed);
    }
    /* add to list package with broken dependencies */
	dlist_add (&((*mlibs)[m_index].pkgname), xstrdup (tgz));
    /* add to list object that require missing library */
    dlist_add (&((*mlibs)[m_index].object), xstrdup (file));
       
	if (t_index < 0)
	 ++*n_mlibs;

    }

    fclose (fd);
    if (rlibpath != libpath)
     free (rlibpath);
    cleanup(Elf, 0);
    return EXIT_SUCCESS;
}

#undef cleanup
