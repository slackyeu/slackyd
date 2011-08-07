/*
 *      search.c
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

/* Verify packages list retreived.
 * If `verbose' is false, never print warnings.
 * Return number of missing files, or -1 if packages list never was update.  
 */
int
packages_list_check (bool verbose, int flags)
{
    const char *strbranch[BRANCHES] = { "/patches", "", "/extra" };
    const char *strfiles []         = { PACKAGES, MANIFEST, NULL };
    const char *cache               = opt.cache;
    
    unsigned r, b, f, missing = 0, ok = 0;
    char path[BUFFSIZE0];
    bool slackware = false, printw = (verbose && opt.warn);
    
    r = 0;
    while (r < N_REPOS)
    {
        if (REPOS[r].SLACKWARE && slackware)
        {
            r++;
            continue;
        }

        /* test FILELIST.TXT */
        snprintf (path, BUFFSIZE, "%s/%s/%s", cache, REPOS[r].name, FILELIST);
        if (!file_exist (path, NULL, true))
        {
            if (printw) fprintf (stderr, "Warning: missing file `%s'\n", path);
            missing++;
        }
        else ok++;

        /* test CHECKSUMS.md5 */
        snprintf (path, BUFFSIZE, "%s/%s/%s", cache, REPOS[r].name, CHECKSUMS);
        if (!file_exist (path, NULL, true))
        {
            if (printw) fprintf (stderr, "Warning: missing file `%s'\n", path);
            missing++;
        }
        else ok++;
            

        for (b = 0; b < BRANCHES; b++)
        {

        if (!REPOS[r].SLACKWARE)
         b++; /* first branch is patches, extra repositories has not it */
        
        for (f = 0; strfiles[f] != NULL; f++)
        {
            snprintf (path, BUFFSIZE, "%s/%s%s/%s",
                cache, REPOS[r].name, strbranch[b], strfiles [f]);

            if (!file_exist (path, NULL, true))
            {
                if (printw) fprintf (stderr, "Warning: missing file `%s'\n", path);
                missing++;
            }
            else ok++;
        }
        
        if (!REPOS[r].SLACKWARE)
         break; /* next branch is extra, extra mirror have not it */
        else
         slackware = true;
        
        }
        
        r++;
    }

    if ((flags == PKGLIST_CHECK_QUIT_ALWAIS && missing > 0) /* one or more files missing */
     || (flags == PKGLIST_CHECK_QUIT_ON_ALL && ok == 0)) /* all files missing */
    {
        /* If verbose is false but something - but no all - miss,
         * check again but before quit print missing files :D */
        if (!verbose && ok > 0 && flags == PKGLIST_CHECK_QUIT_ALWAIS)
         return packages_list_check (true, flags);
         
        fprintf (stderr, "%s"
         "Error, you need to update packages list.\n"
         "Run `slackyd -u' or `slackyd -f -u' to force.\n\n", (verbose && opt.warn) ? "\n" : "");
        exit (1);
    }

    if (printw && missing > 0)
     fprintf (stderr, "Try to update packages list.\n\n");

    return (ok > 0) ? (int) missing : -1;
}


/* Test installed packages for `pkg' pkg_t type.
 * If package is installed return PACKAGE_STATUS_INSTALLED, else
 * if package is not installed return PACKAGE_STATUS_NOT_INSTALLED.
 * If is installed a package with same name, but with different version, arch and/or
 * build, return his index in global list `ginst'.
 */
static int
pkg_inst_status (pkg_t *pkg)
{
    unsigned i = 0;
    int rval;
    char *x;

    x = strcasestr (pkg->name, ".txz\0");
    if (x == NULL) {
        x = strcasestr (pkg->name, ".tgz\0");
    }
        
    
    for (; i < nginst; i++)
    {
        if (strcmp (ginst[i].pstruct.name, pkg->pstruct.name) == 0)
        {
            if (x) *x = 0x00; /* installed packages list hasn't extension */
            rval = strcmp (ginst[i].name, pkg->name);
            if (x) *x = '.';
            return (rval == 0) ? PACKAGE_STATUS_INSTALLED : (int) i;
        }
    }

    return PACKAGE_STATUS_NOT_INSTALLED;
 }


/* Verify `s' for package operator.
 * We call this func from save_each_pkg() when split packages required/suggested
 * list.
 */
static bool
isop (char *s)
{    
	static const char *op[] = { ">=", ">", "=", "==", "<=", "<", NULL };
	unsigned short i = 0;
	
	slassert (s && s[0]);
	
	while (op[i])
	 if (strcmp (s, op[i++]) == 0)
	  return true;
	 
	return false;
}

/* Save each package from `data' string in `dlist' apposite structure, see slackyd.h.
 * Save in `n' number of packages read.
 * If `regval' is 0 and `data' in NULL, we assume that regex is failed and keyword
 * not present, then we set `n' to FEATURE_UNAVAILABLE. Otherwise, if `regval' is non zero
 * and `s' is NULL, set `n' to FEATURE_NOTHIN_SPEC.
 */ 
static void
save_each_pkg (char *data, dep_t **deplist, int *n, int regval, int flag)
{
    char *s = NULL, *p = NULL, *addr = NULL;
    dlist *tokens = NULL, *current;
	char *name, *op, *version;
	bool ornext = 0;
	
    /* if data is NULL set n to feature unspecificed or to feature unavailable,
     * depending to `regval' value (regexec(), see parse_pkg_line() down). */
    if (data == NULL) {
        *n = (regval == 0x00) ? FEATURE_NOTHING_SPEC : FEATURE_UNAVAILABLE;
		return;
    }
	
	s = xstrdup(data);
    addr = s;

    /* Package string maybe "abc >= 1,cde >= 1" or "abc >= 1 cde >= 1".
     * Comma or white space separated.
     */
    p = strtok(s, " ,\t");
    if (!p)
	{
		free (addr);
		*n = FEATURE_NOTHING_SPEC;
		return;
    }

    /* save each token in temporarey dynamic strings list */
    do
	{
		dlist_add (&tokens, xstrdup (p));

	} while ((p = strtok (NULL, " ,\t")) != NULL);

    *n = 0x00;
    /* for each token check for operator and save name, operator and version (if possibile) in apposite
     * structure.
     */
    current = tokens;
    ornext  = false;
	while (current)
	{        
        name = current->s;
		op = version = NULL;

		if (current->next && current->next->next)
		{
			op      = current->next->s;
			version = current->next->next->s;

			if (!isop (op) || isop (version))
			{
				op = version = NULL;
			}
		}
		
		add_dep (name, op, version, flag, deplist, n);

		current = (op && version) ? current->next->next->next : current->next;

		ornext = (current && strcmp (current->s, "|") == 0 && (current = current->next)) ? 1 : 0;
		
		(*deplist)[*n - 1].OR_next = ornext;
		(*deplist)[*n - 1].missing = !(missing_required_ok (&(*deplist)[*n - 1]));

    }

    free (addr);
    dlist_free (&tokens);

    return ;
}


/* Parse package data line `data'.
 * `act' set type of line, _PKG_NAME, _PKG_REQ, _PKG_LOC etc. See slackyd.h.
 * Save data matched in members of apposite `pkg' pkg_t struct.
 *
 * Note:
 *    We use `tlen' to set additional offset of our match.
 *    See strregdup() above.
 *    We use also `token' under `act' status to set keyword to match.
 *    See slackyd.h.
 */
static void
parse_pkgline (char *data, short act, pkg_t **pkg)
{
    char regex[WORDSIZE0];
    regex_t re;
    regmatch_t match;
    char *buff = NULL;
    int tlen = 0x00, cflags = 0x00, regval = 0x00;
    char *token = NULL;

    switch (act) {
        case _PKG_NAME  :  token = PKG_NAME;    break;
        case _PKG_LOC   :  token = PKG_LOC;     break;
        case _PKG_SIZE_C:  token = PKG_SIZE_C; tlen -= 2;  break; /* ignore '(' and ')' */
        case _PKG_SIZE_U:  token = PKG_SIZE_U; tlen -= 2;  break; /* ignore '(' and ')' */
        case _PKG_REQ   :  token = PKG_REQ;     break;
        case _PKG_CNFLT :  token = PKG_CNFLT;   break;
        case _PKG_SGST  :  token = PKG_SGST;    break;
        default:
            slassert (NULL);
            break;
    }
    tlen  += strlen (token);
    
    memset (regex, 0, WORDSIZE0);
    snprintf (regex, WORDSIZE, "(%s)(.*)$", token);
	cflags = REG_EXTENDED | REG_NEWLINE;
    xregcomp (&re, regex, cflags);

    if ((regval = regexec (&re, data, 1, &match, 0)) == 0x00) {
        buff = strregdup (data, match, tlen);
    }
	regfree (&re);
	
	
    switch (act) {
        case _PKG_NAME: (*pkg)->name     = buff; return; break; /* no free buff here */
        case _PKG_LOC:  (*pkg)->location = buff; return; break; /* no free buff here */
        case _PKG_SIZE_C:
            (*pkg)->size_c = (!regval) ? atoi (buff) : -1;
            break;
        case _PKG_SIZE_U:
            (*pkg)->size_u = (!regval) ? atoi (buff) : -1;
            break;
        case _PKG_REQ:
            save_each_pkg (buff, &(*pkg)->required,  &(*pkg)->nrequired, regval, DEP_T_REQUIRED);
            break;
        case _PKG_CNFLT:
            save_each_pkg (buff, &(*pkg)->conflicts, &(*pkg)->nconflicts, regval, DEP_T_CONFLICT);
            break;
        case _PKG_SGST:
            save_each_pkg (buff, &(*pkg)->suggests,  &(*pkg)->nsuggests, regval, DEP_T_SUGGESTED);
            break;
        default:
            slassert (NULL);
            break;
    }

    free (buff);
    return ;
}


/* Parse package description on global package data `data'.
 * Save description in `desc' member of `pkg' structure.
 * If description not found set `desc' member to NULL.
 */
static void
parse_pkgdesc (char *data, pkg_t **pkg)
{
    char *begin = NULL, *p;
    int len;
    
    (*pkg)->desc = NULL;

    /* Match begin and last newlines of our description. */
    begin = strstr (data, PKG_DESC);

    /* if description keyword not found return. */
    if (!begin)
     return;
    begin += strlen (PKG_DESC);

    while (isspace (begin[0]))
     begin++;

    if (!begin[0])
     return;

    len = strlen (begin);
    (*pkg)->desc = xmalloc ((len + 1) * sizeof (char));
    memset ((*pkg)->desc, 0, len + 1);

    while (begin[0])
    {
        if ((p = strchr (begin, ':')))
         begin = p + 1;

        if ((p = strchr (begin, '\n')) == NULL)
         break;

        *p = 0x00;
        strcat ((*pkg)->desc, "::");
        strcat ((*pkg)->desc, begin);
        strcat ((*pkg)->desc, "\n");
        begin = p + 1;
    }
    
    return;
}
        
    
/* Split packages data saved in `pkgdata` and save them in pkg_l list. Return it.
 * Packages data was read from `b' branch of `r' repository from config file.
 * List can be converted to an array using pkgl2pkgt() and must be freed using
 * pkgl_free() or pkg_t_free_all().
 */
pkg_l *
save_pkg_data (dlist *pkgdata, int r, int b)
{
	dlist *current = pkgdata;
	pkg_t *p = NULL;
	pkg_l *pkglist = NULL;

    int inst_index = 0;
	
	while (current) {

    p = malloc (sizeof (pkg_t));
    
    p->required   = NULL;
    p->nrequired  = FEATURE_DISABLED;
    p->conflicts  = NULL;
    p->nconflicts = FEATURE_DISABLED;
    p->suggests   = NULL;
    p->nsuggests  = FEATURE_DISABLED;
    p->installed  = NULL;
    p->status     = PACKAGE_STATUS_NOT_CHECKED;
    p->desc       = NULL;
    	
	parse_pkgline (current->s, _PKG_NAME, &p);

	if (!p->name
     || split_pkg (p->name, &p->pstruct))
	{
	    free (p->name);
	    free (p);
	    current = current->next;
        continue;
    }
    
    p->blacklisted = is_blacklisted (p->name);

    if (opt.blacklist && p->blacklisted)
    {
        free (p->name);
	    free (p);
	    current = current->next;
        continue;
    }

    parse_pkgline (current->s, _PKG_LOC, &p);

    if (p->location == NULL)
    {
        free (p->name);
        free (p);
        current = current->next;
        continue;
    }
	  

    if (p_fold.size_c)
     parse_pkgline (current->s, _PKG_SIZE_C, &p);
	
	if (p_fold.size_u)
     parse_pkgline (current->s, _PKG_SIZE_U, &p);
	
	if (p_fold.req)
     parse_pkgline (current->s, _PKG_REQ,    &p);

	if (p_fold.conflict)
     parse_pkgline (current->s, _PKG_CNFLT,  &p);

	if (p_fold.suggest)
     parse_pkgline (current->s, _PKG_SGST,   &p);

    if (p_fold.desc)
     parse_pkgdesc (current->s, &p);


	inst_index = pkg_inst_status (p);
	p->status = inst_index;
	if (inst_index >= 0)
	 p->installed = xstrdup (ginst[inst_index].name);

    if (r >= 0)
     p->N_REPO = (unsigned) r;

    if (b >= 0)
     p->branch = (branches) b;
     
    
    pkgl_add (&pkglist, p);
    current = current->next;

    }	/* end while() */

    return pkglist;
}

/* Search packages `name' in all repositories list, using `flag' research policy.
 * See search_pkg().
 * Return a list of packages found.
 */
pkg_l *
search (short flag, const char *name)
{
    unsigned r, b;
    char path[BUFFSIZE0];
    bool slackware = false;
    dlist *pkgdata = NULL;
    pkg_l *pkglist = NULL;

    /* for each repository ... */
    for (r = 0; r < N_REPOS; r++)
    {

    /* we use just one official repository */
    if (REPOS[r].SLACKWARE && slackware)
    {
        continue;
    }
    else
    {
        if (REPOS[r].SLACKWARE && !slackware)
        {
            slackware = true;
        }
    }

    /* for each branch ... */
    for (b = 0; b < BRANCHES; b++)
    {

    /* if current repository is extra we increment j.
     * First `sbranch' string is "patches", extra repository haven't them !
     */
    if (!REPOS[r].SLACKWARE)
    {
        b++;
    }

    snprintf (path, BUFFSIZE, "%s", make_rpath (r, b, PACKAGES));

    if (search_pkg (&pkgdata, flag, path, name) > 0)
    {
        pkgl_join (&pkglist, save_pkg_data (pkgdata, (int) r, (int) b));
        dlist_free (&pkgdata);
    }
        
    if (!REPOS[r].SLACKWARE)
    {
        break; /* extra repository haven't patches or extra */
    }

    }
	}

	return pkglist;
}


/* Check version of package `found' required by `required'.
 * Note: `required' isn't a package type pkg_t, normally is
 * just a required type dep_t contained in the same pkg_t structure (ex: mrequired)
 */
bool
required_ok (dep_t *required, pkg_t *found)
{
    int diffver = 0;

    if (strcmp (required->name, found->pstruct.name))
	 return false;

	 /* If no version is specificed we assume after that all version available are ok */
    if (required->version != NULL)
	{
		diffver = strverscmp (found->pstruct.version, required->version);
	}
	
    switch (required->op_t) {
        case VERSION_ALL:
            return true;
            break;
        case VERSION_MINOR:
            return (diffver < 0)  ?  true : false;
            break;
        case VERSION_MINOR_OR_EQUAL:
            return (diffver <= 0) ?  true : false;
            break;
        case VERSION_EQUAL:
            return (diffver == 0) ?  true : false;
            break;
        case VERSION_MAJOR:
            return (diffver > 0)  ?  true : false;
            break;
        case VERSION_MAJOR_OR_EQUAL:
            return (diffver >= 0) ?  true : false;
            break;
        default:
            slassert (NULL);
            break;
        
        }

    return 0;
}

/* Check status of a package required.
 * We can not call directly required_ok() function because it
 * receive also a pkg_t pointer.
 */
bool
missing_required_ok (dep_t *required)
{
    pkg_t tmp;
    int rval = 0;
    unsigned pos = 0;

    /* Check for package status, parsing only name.
     * If something was found return his index in global installed
     * packages list `ginst', see slackyd.h.
     */
    do {
        rval = is_installed (required->name, MATCH_EXACTLY_NAME, pos);
        if (rval == PACKAGE_STATUS_NOT_INSTALLED)
         return false;

        tmp.name    = ginst[rval].name;
        tmp.pstruct = ginst[rval].pstruct;

        /* return true if version is ok */
        if (required_ok (required, &tmp))
         return true;
        
        /* Continue with next packages, if they exist.
         * We parse all occurrances and make sure that
         * required package is really missing !
         * For example we can have installed abc 1.0 e abc 2.0;
         * if abc >= 2.0 is required, without this while slackyd assume
         * that abc is missing, because installed packages list is
         * alpha-sorted and slackyd will find abc 1.0 BEFORE abc 2.0 :).
         */
        pos = rval + 1;

     } while (rval != PACKAGE_STATUS_NOT_INSTALLED);

     return false;
}


/* A search_pkg() helper =D
 * Check if package string `s' is conform to match `set_match' (see search_pkg() above).
 */
static bool
pkg_ok (short set_match, regex_t *preg, char *s, const char *pkgname)
{
    char *ptr, *e, buffer[BUFFSIZE0];
    int l;
    pkg_struct tmpstruct;
    
    /* test for initial package data, must be:
     * PACKAGE NAME:  packagename-version-arch-build.tgz
     */
    if (strncmp (s, PKG_NAME, strlen (PKG_NAME)))
    {
        return false;
    }

    /* Now `copy in a buffer package string without initial "PACKAGE NAME:"
     * and use `ptr' to remove some characters as spaces tab etc... 
     * `ptr' will containe exactly package name, we parse only it, using regex or not.
     */
    strncpy (buffer, s + strlen (PKG_NAME), BUFFSIZE);
    ptr = buffer;

    while (strchr (" :\r\n", ptr[0]))
    {
        ptr++;
    }
    
    if (!((e = strcasestr (ptr, ".tgz")) || (e = strcasestr (ptr, ".txz"))))
    {
        return false;
    }
    
    if (!isascii (*(e + 4)))
    {
        return false;
    }

    *(e + 4) = 0x00; /* remove spaces, tab or other after package extension */
    

    switch (set_match)
    {

        case MATCH_ALL_NAME:
            if (!pkgname)
            {
                return true; /* we want all */
            }
            else
            {
                return (xstrstr (ptr, pkgname)) ? true : false;
            }
            
            break;


        case MATCH_EXACTLY_NAME:

            return (xstrstr (ptr, pkgname)
                 && regexec (preg, ptr, 0, NULL, 0) == 0) ? true : false;

            break;


        case MATCH_EXACTLY_PACKAGE:

            return (!strcmp (ptr, pkgname)) ? true : false;

            break;


        case MATCH_USING_REGEX:

            return (regexec (preg, ptr, 0, NULL, 0) == 0) ? true : false;

            break;


        case MATCH_EXACTLY_NAME_INST:
            /* Search package installed by name;
             * For example where `ptr' is "abc-1.2-i486-1.tgz" and we have
             * installed "abc-1.3...", it will be matched because here we
             * consider only package name.
             * If `pkgname' is NULL match all package available with name
             * of one or more packages installed !
             *
             * NOTE: If `pkgname' is non-NULL and isn't contained in `ptr',
             * we return immediatly.
             */
            return ( (!pkgname || xstrstr (ptr, pkgname))
                 &&  !split_pkg (ptr, &tmpstruct)
                 &&  is_installed (tmpstruct.name, MATCH_EXACTLY_NAME, 0) >= 0) ? true : false;

            break;
        

        case MATCH_EXACTLY_PACKAGE_INST:
            /* Search all packages available and installed.
             * Entire package string will be compared.
             */
            if (pkgname && !xstrstr (ptr, pkgname))
            {
                return false;
            }

            l = strlen  (ptr) - 4;

            if (!strncasecmp (ptr + l, ".tgz", 4) || !strncasecmp (ptr + l, ".txz", 4))
            {
                ptr[l] = 0x00;
            }

            return (is_installed (ptr, MATCH_EXACTLY_PACKAGE, 0) >= 0) ? true : false;

            break;


        case MATCH_ALL_NAME_BLACK:

            slassert (!opt.blacklist);

            if (pkgname && !xstrstr (ptr, pkgname))
            {
                return false;
            }

            return (bool) is_blacklisted (ptr);

            break;


        case MATCH_ALL_NAME_BLACK_REG:

            slassert (!opt.blacklist);

            return (!regexec (preg, ptr, 0, NULL, 0)
                 && is_blacklisted (ptr)) ? true : false;

            break;
 
        default:
            slassert (NULL);
            break;
        
        }

    return false;
}

/* Find package name `pkgname' in `path' file list and save data in `datalist'.
 *
 * 'set_match' value set regex:
 *  MATCH_ALL_NAME       : match packages by name (*name*") or all if NULL is used.
 *  MATCH_EXACTLY_NAME   : match packages by exactly name (name-*").
 *  MATCH_EXACTLY_PACKAGE: match packages by exactly string (name-version-arch-build.tgz).
 *  MATCH_USING_REGEX    : use regex.
 *  MATCH_ALL_NAME_BLACK : blacklisted packages.
 *  If "_INST" variant is used, package must be also installed.
 *  For example MATCH_ALL_ALL_INST match all packages available but also installed.
 * 
 *  Save results in `datalist'. Return number of strings saved.
 */
int
search_pkg (dlist **datalist, short set_match, char *path, const char *pkgname)
{
    FILE *fd;
    regex_t re;
    int saved = 0, rval, cflags = REG_EXTENDED | REG_NEWLINE | REG_NOSUB;
    unsigned long dsize = 0;
    char buffer[HUGE0], regex[BUFFSIZE0];

    if (!(fd = fopen (path, "r"))) {
        return -1;
    }

    /* fix package name regex */
    if (!pkgname)
     slassert (set_match != MATCH_EXACTLY_NAME
            && set_match != MATCH_EXACTLY_PACKAGE);

    switch (set_match) {
        case MATCH_EXACTLY_NAME:
	        snprintf (regex, BUFFSIZE,
	          "^%s\\-[^-]+\\-[^-]+\\-[^-]+\\.t[gx]z$" , set_regex (pkgname));
	        break;
        case MATCH_USING_REGEX:
        case MATCH_ALL_NAME_BLACK_REG:
            slassert (pkgname != NULL);
            strncpy (regex, pkgname, BUFFSIZE);
            break;
        default:
            strcpy (regex, ""); /* we compile anyway regex, also when we don't execute it */
            break;
    }
    
    /* compile expression */
    if (opt.case_insensitive)
    {
        cflags |= REG_ICASE;
    }
    xregcomp (&re, regex, cflags);
            
    /* search package in repository file */
    while (fgets (buffer, HUGE, fd)) {
    
    /* check for package ok */
    if (!pkg_ok (set_match, &re, buffer, pkgname))
    {
        continue;
    }

    /* find end of packages desc (\n\n) and add data to pkgfound array */
    dsize = strlen (buffer); /* "PACKAGE NAME: ..." */

    /* read other data untill end of file of a void line */
    while (fgets (buffer, HUGE, fd) && buffer[0] != '\n')
    {
        dsize += strlen (buffer);
    }

    /* check for max buffer size */
    if (dsize > HUGE)
    {
        printfw ("\n"
            "*** Warning:\n"
            "Some package data found in file `%s' "
            "seems to be too long. Continuing.\n", path);
        continue;
    }

    /* go back to package data begin */
    if (fseek (fd, -dsize - 1, SEEK_CUR) != 0)
    {
        printfw ("\n"
            "*** Warning:\n"
            "Seek of file `%s' failed: %s. "
            "Continuing.\n", path, strerror (errno));
        continue;
    }

    /* read again data, close string with a 0 and add to dynamic strings list. */
    if ((rval = fread (buffer, 1, dsize, fd)) < (int) dsize)
    {
        printfw ("\n"
                "*** Warning:\n"
                "Cannot read from %s: %s. "
                "Continuing.\n", path, strerror (errno));
         fseek (fd, dsize - rval, SEEK_CUR);
         continue;
    }

    buffer[rval] = 0x00;
    
    dlist_add (datalist, xstrdup (buffer));
    ++saved;
    }

   regfree (&re);
   fclose (fd);
   
   return saved;
}


/* read all packages installed and conform to pkgtools standard,
 * save entire name and split it in apposite installed_t pkg_struct sub structure.
 * Return number of packages read and saved, they must will free
 * with free_installed_t () !
 */
unsigned 
installed (installed_t **list)
{
    struct dirent **namelist;
    int n, i;
    unsigned total = 0x00;
    pkg_struct tmpstruct;

    *list = NULL;
    
    n = scandir (PKGDIR, &namelist, 0, alphasort);
    
    if (n < 0)
    _error (5, "\n"
    "Cannot open ", PKGDIR, ": ", strerror (errno), ".\n\n");
	
    if (n <= 2) /* . and .. */
	_error (3, "\n"
	"Directory ", PKGDIR, " seems to be void !?\n\n");
	
    /* ignore . and .. directories */
    free (namelist[0]);
    free (namelist[1]);
    n -= 2;
    for (i = 0; i < n; i++) {
        /* we want just packages conform to pkgtools :) */
        if (!split_pkg (namelist[i + 2]->d_name, &tmpstruct)) {
            (*list) = (installed_t *)
                xrealloc ((*list), (total + 1) * sizeof (installed_t));
            (*list)[total].name    = xstrdup (namelist[i + 2]->d_name);
	        (*list)[total].pstruct = tmpstruct;
	        total++;
        }
        free (namelist[i + 2]);
    }

    free (namelist);
    return total;
}

static void
quick_pkg_t (pkg_t **v[], unsigned start, unsigned end)
{
    int l,r, val1, val2, val3;
    pkg_t *ptmp;
    
    
    if (end > start + 1)
    {
         
        l = start + 1;
        r = end;
	
        while (l < r) {
    	     	
        val1 = strcmp ((*v)[l]->pstruct.name,    (*v)[start]->pstruct.name);
        val2 = strcmp ((*v)[l]->pstruct.version, (*v)[start]->pstruct.version);
        val3 = atoi ((*v)[l]->pstruct.build) - atoi ((*v)[start]->pstruct.build);

        if ( (val1 < 0) || (!val1 && val2 > 0) || (!val1 && !val2 && val3 > 0) )
        {
            l++;
        }
        else
        {
            ptmp    = (*v)[l];
            (*v)[l] = (*v)[--r];
            (*v)[r] = ptmp;
        }

        }
        
			
        ptmp        = (*v)[--l];
        (*v)[l]     = (*v)[start];
        (*v)[start] = ptmp;

        quick_pkg_t (v, start, l);
        quick_pkg_t (v, r, end);
    }

    return;
}


/* sort a list of pkt_t and destroy packages not standard */
void
sort_pkg (pkg_t **list[], unsigned *n_list)
{
	if (*n_list == 0)
	 return;
	
	quick_pkg_t (list, 0, *n_list);
}


/* search in all MANIFEST required file contained in `libneed_t' structure.
 * Add packages found to same structure, see slackyd.h.
 * Return number of required packages found and added.
 */ 
unsigned
search_shared_dep (libneed_t *need)
{
    FILE *fd;
    char buffer[BUFFSIZE0];
    char *current = NULL, *ptr;
    unsigned i, j, ch = 0;
    bool slackware = false;
    dlist *tmpdata = NULL;
    pkg_l *pkglist = NULL;
    char regex[BUFFSIZE0];
    regex_t preg;

    opt.blacklist = false;
    need->packages = NULL;

    /* in our regex we can't match exactly library name because
     * on executable maybe linked a symbolic link, and it is not present in MANIFEST :(
     */
    snprintf (regex, BUFFSIZE, "^\\-.*/%s[\\.0-9]*$", set_regex (need->needed));
    
    xregcomp (&preg, regex, REG_EXTENDED | REG_NEWLINE | REG_NOSUB);
    
    /* for each repository ... */
    for (i = 0; i < N_REPOS; i++)
    {
    
    if (REPOS[i].SLACKWARE && slackware)
    {
        continue; /* we have already search in official manifest */
    }
    
    /* for each branch (if repository is official)... */
    for (j = 0; j < BRANCHES; j++)
    {
    
    /* if current repository is extra increment branch index
     * because we use _PATCHES as first branch !
     * See slackyd.h and packages.c (make_rpath function).
     */
    if (!REPOS[i].SLACKWARE)
     j++;
    snprintf (buffer, BUFFSIZE, "%s", make_rpath (i, j, MANIFEST));
         
    if (!(fd = fopen (buffer, "r")) || get_file_size (fd) == 0)
    {
        if (REPOS[i].SLACKWARE)
         continue;
        else
         break; /* extra repositories haven't patches or extra branch */ 
    }

    while (fgets (buffer, BUFFSIZE, fd))
    {
        if (strstr (buffer, "||   Package:"))
        {
            free (current);
            current = xstrdup (strrchr (buffer, '/') + 1);
        }
        else /* we use strstr() before regexec because is very fast :) */
        if (strstr (buffer, need->needed) && !regexec (&preg, buffer, 0, NULL, 0))
        {
            /* missing library found in package `current' ! */

            if (!(ptr = strcasestr (current, ".txz\0")) && !(ptr = strcasestr (current, ".tgz\0")))
            {
                continue;
            }
            else
            {
                *(ptr + 4) = 0x00;
            }
            
            snprintf (buffer, BUFFSIZE, make_rpath (i, j, PACKAGES));
            
            if (search_pkg (&tmpdata, MATCH_EXACTLY_PACKAGE, buffer, current) > 0)
            {
                pkglist = save_pkg_data (tmpdata, i, j);
                dlist_free (&tmpdata);
            }
            else
            {
                pkglist = NULL;
            }

            switch (pkgl_count (pkglist))
            {
                case 0:
                    printf ("`%s' missing from %s's packages list...", current, REPOS[i].name);
                    break;
                case 1:
                    if (!pkgl_check (pkglist->p->name, need->packages, MATCH_EXACTLY_PACKAGE))
                    {
                        pkgl_add (&need->packages, pkglist->p);
                    }
                    free (pkglist); /* `p' member was 'linked' above, we not free it here :) */
                    break;
                default:
                    pkgl_free (&pkglist);
                    printf ("too `%s' in %s's packages list, ignoring...", current, REPOS[i].name);
                    break;
            }
        }
    }

    ch++;
    fclose (fd);

    if (!REPOS[i].SLACKWARE)
     break; /* we will not search in extra or patches branch */
    
 	} /* end branch for() */
        
    if (REPOS[i].SLACKWARE && !slackware)
     slackware = true; 
        
    } /* end for() */	
    

    regfree (&preg);
    free (current);
    
    if (ch == 0)
    _error (1, "\n\n"
    "Error, no MANIFEST files found.\n"
    "Try to update or fix your slackyd.conf.\n\n");

    return pkgl_count (need->packages);
}
