/*
 *      packages.c
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

/* make repository path for file `file' and mirror `rindex'
 * of external REPOS repository type list, from branch `branch'.
 */
char *
make_rpath (unsigned rindex, branches branch, const char *file) {

    unsigned r = rindex;
    branches b = branch;
    const char *STR_BRANCH[BRANCHES] = { "patches", "", "extra" };
    const char *cache = opt.cache, *rname, *bname;
    static char rpath[BUFFSIZE0];
    
    memset (rpath, 0, BUFFSIZE0);

    slassert (file);
    slassert (rindex < N_REPOS);
    slassert (branch < BRANCHES);
    if (!REPOS[r].SLACKWARE) {
        slassert (branch == _PACKAGES)
    }

    rname = REPOS[r].name;
    bname = STR_BRANCH[b];
    
     switch (b)
     {
        case _PACKAGES:
            snprintf (rpath, BUFFSIZE, "%s/%s/%s", cache, rname, file);
            break;
        default:
            snprintf (rpath, BUFFSIZE, "%s/%s/%s/%s", cache, rname, bname, file);
            break;
    }
    
    return rpath;
}


char *
pkg_type (pkg_t *package)
{
    static char type[BUFFSIZE0], strstat[WORDSIZE0];
    const char *sbranch[BRANCHES] = { "security fix ", "", "extra package " };
    unsigned r = package->N_REPO;
    branches b = package->branch;

    memset (type, 0, BUFFSIZE);

    /* If we are searching packages to upgrade skip package status string compiling.
     * Package is installed, stop :)
     */
    if (opt.verbose && opt.print_status)
    switch (package->status)
    {
        case PACKAGE_STATUS_NOT_CHECKED:
            strstat[0] = '\b';
            strstat[1] = 0x00;
            break;
        case PACKAGE_STATUS_NOT_INSTALLED:
            strncpy (strstat, "\b, not installed", WORDSIZE);
            break;
        case PACKAGE_STATUS_INSTALLED:
            strncpy (strstat, "\b, installed", WORDSIZE);
            break;
        default:
            snprintf (strstat, WORDSIZE, "\b, installed %s", package->installed);
            break;
    }
    else {
        strstat[0] = '\b';
        strstat[1] = 0x00;
    }

    /* paranoid, force branch if repository is extra */
    if (!REPOS[r].SLACKWARE)
     package->branch = b = _PACKAGES;
    
    if (opt.verbose && package->size_c > 0 && package->size_u > 0)
     snprintf (type, BUFFSIZE, "[%d KB -> %d KB, %sfrom %s %s]",
        package->size_c,
        package->size_u,
        sbranch[b],
        REPOS[r].name,
        strstat);
    else
    if (opt.verbose)
     snprintf (type, BUFFSIZE, "[%sfrom %s %s]",
        sbranch[b],
        REPOS[r].name,
        strstat);
    else
     snprintf (type, BUFFSIZE, "[%sfrom %s]",
        sbranch[b],
        REPOS[r].name);
    
        
    return type;
}

int
have_missing_req (pkg_t *pkg)
{
	int i;

	for (i = 0; i < pkg->nrequired; i++)
	{
		if (pkg->required[i].missing)
		{
			return 1;
		}
	}
	return 0;
}

int
have_missing_sug (pkg_t *pkg)
{
	int i;

	for (i = 0; i < pkg->nsuggests; i++)
	{
		if (pkg->suggests[i].missing)
		{
			return 1;
		}
	}
	return 0;
}

char
is_blacklisted (const char *name)
{
    unsigned i, n = opt.nblacklisted;

    if (!n) {
        return 0;
    }

    for (i = 0; i < n; i++) {
        if (regexec (&opt.blacklisted[i], name, 0, NULL, 0) == 0x00) {
            return 1; /* blacklisted */
        }
    }

    return 0;
}

/* print `n' `packages' data (name and if verbose switch is
 * actived also print package compressed/uncompressed size and package status).
 * See pkg_type() above !
 */
void
show_pkg_found (pkg_t **packages, unsigned n)
{
    unsigned i;
    
    for (i = 0; i < n; i++)
    {
        if (!opt.blacklist || !packages[i]->blacklisted)
        {
            fprintf (stdout, "%s %s\n", packages[i]->name, pkg_type (packages[i]));
        }
    }
    
    return;
}


/* normally our packages list is alpha-sorted.
 * This function simply search same packages (only name).
 */ 
static unsigned
same_pkg (pkg_t *packages[], unsigned n, unsigned index)
{
    unsigned i = index + 1, p = 1;

    while (i < n)
    if (strcmp (packages[index]->pstruct.name, packages[i++]->pstruct.name) == 0)
     ++p;
    else
     break;

    return p;
}

/* this function remove from `n' elements list packages with same name of `packages[index]`.
 * All next package with same same will be removed !
 * This because on download, for example, we may want get just one package on all !
 */
static void
rm_same (pkg_t **packages[], unsigned *n, unsigned index)
{
    unsigned i = index;

    while (*n > 0 && i < *n - 1
        && strcmp ((*packages)[i]->pstruct.name, (*packages)[i + 1]->pstruct.name) == 0)
    {
        pkg_t_rm (packages, n, i + 1);
    }

    return;
}
    

/* download package(s) */
void
get (pkg_t **packages[], unsigned *n_pkgs)
{
    unsigned i, j, c, same;
    unsigned n_dep = 0, instcnt = 0, choosed = 0, not_choosed = 0, downloaded = 0;
    pkg_t **dep = NULL;
    choose_dep_t ddata;
	bool ch;

    if (*n_pkgs == 0)
     return;

    memset (&ddata, 0, sizeof (ddata));
	putchar ('\n');

    /* for each element in `package' array */
    for (i = 0; i < *n_pkgs; ) {

	if (pkgl_check ((*packages)[i]->pstruct.name, ddata.added, MATCH_EXACTLY_NAME))
	{
		pkg_t_rm (packages, n_pkgs, i);
		continue;
	}

    /* check for package already installed */
    if (!opt.skip_status && (*packages)[i]->status >= PACKAGE_STATUS_INSTALLED)
    {
        if (opt.warn)
        {
            fprintf (stdout, "*** %s: already installed", (*packages)[i]->name);
            if ((*packages)[i]->status > PACKAGE_STATUS_INSTALLED)
			{
				fprintf (stdout, " (%s)", (*packages)[i]->installed);
			}
            fprintf (stdout, ".\n");
        }
        pkg_t_rm (packages, n_pkgs, i);
        instcnt++;
        continue;
    }

    same = same_pkg (*packages, *n_pkgs, i);

    if (same > 1)
    {
        fprintf (stdout, "Found %d different version of %s:\n", same, (*packages)[i]->pstruct.name);

		for (j = 0; j < same; j++)
        {
			fprintf (stdout, " --> %s\n", (*packages)[i + j]->name);
        }

		if (opt.force)
        {
            fprintf (stdout, "Will be used %s %s\n", (*packages)[i]->name, pkg_type ((*packages)[i]));
            rm_same (packages, n_pkgs, i);
	    }
    }

    ch = false;
    if (opt.force)
    {
		ch = true;
    }
	else
    do
    {
        fprintf (stdout, "Download %s %s ? [y/N] ", (*packages)[i]->name, pkg_type ((*packages)[i]));
	    fflush (stdout);

		if ((c = getc(stdin)) == 'Y' || c == 'y')
	    {
	        rm_same (packages, n_pkgs, i);
	        ch = true;
        }
        else
        {
            --same;
            pkg_t_rm (packages, n_pkgs, i);
        }

		if (c != '\n')
         clrbuff();

	} while (!ch && same > 0 && *n_pkgs > 0);

    if (!ch)
    {
        not_choosed++;
        continue;
    }
     
    choosed++;
	i++;
    
    /* search missing packages required in repository.
     * If found ask if download. */
	if (opt.check_dep && opt.resolve_dep)
    {
		ddata.next  = *packages;
		ddata.nnext = i;
		choice_dep (&ddata, (*packages)[i - 1], DEP_T_REQUIRED);
		choice_dep (&ddata, (*packages)[i - 1], DEP_T_SUGGESTED);
	}

    } /* end for() */


    if (instcnt     >= *n_pkgs
     && not_choosed == 0
     && choosed     == 0)
    {
         fprintf (stdout, "\nAll packages available are installed.\n");
         return;
    }
    else
    if (choosed == 0)
	{
        fprintf (stdout, "\nNothing was choosed.\n");
        return;
    }

    if (!opt.force)
     putchar ('\n');
    
    /* download dependencies if feature wasn't disabled and verify if check was completed successfull */
    if ((dep = pkgl2pkgt (ddata.added, &n_dep)))
	{
		for (i = 0; i < n_dep; i++)
		{
	    	if (get_pkg (dep[i]) == EXIT_SUCCESS && opt.hash)
			{
				verify_md5 (dep[i]);
			}
		}

		pkg_t_free_all (&dep, n_dep);
	}

    
	/* download packages */
    for (i = 0; i < *n_pkgs; i++)
	{
        if (get_pkg ((*packages)[i]) == EXIT_SUCCESS)
        {
            downloaded++;

			if (opt.hash)
			{
				verify_md5 ((*packages)[i]);
        	}
		}
    }

    /* if notify of broken dependencies was enabled ... */
    if (downloaded > 0 && opt.notify_dep)
	{
		show_missing_req (*packages, *n_pkgs);
		make_missing_req_list (*packages, *n_pkgs);
    }

    return;
}

/* verify md5 sum ok package from argument. */
void
verify_md5 (pkg_t *package)
{
    const char *cache = opt.dest;
    char path[BUFFSIZE0] = { 0 };
    char *hash = NULL;
    unsigned mirror = package->N_REPO; /* mirror index */
    branches branch = _PACKAGES; /* always _PACKAGES (/var/slackyd/mirror/CHECKSUMS.md5" ... */
    char *md5list = make_rpath (mirror, branch, CHECKSUMS);

    /* checksum path */
    hash = getmd5 (package->name, md5list);

	/* downloaded package path */
	snprintf (path, BUFFSIZE, "%s/%s", cache, package->name);
    md5file (path, hash, md5list);

	free (hash);
    return;
}


static char *
strfeature (int val)
{
	static char buffer[8] = { 0 };

	switch (val)
	{
		case FEATURE_UNAVAILABLE:
			return "not available.\n";
			break;
		case FEATURE_NOTHING_SPEC:
			return "nothing.\n";
			break;
		case FEATURE_DISABLED:
			return "disabled.\n";
			break;
		default:
			slassert (val > 0);
			snprintf (buffer, 7, "%u\n", val);
			break;
	}
	return buffer;
}


static void
show_packages_required (pkg_t *package)
{
	const char *status[] = { "[INSTALLED]", "[NOT INSTALLED]" };
    char *name, *op, *version;
	bool next;
    int i, count, missing;
    
    fprintf (stdout, "> Packages required: %s", strfeature (package->nrequired));
    
    for (i = 0; i < package->nrequired; )
	{
		count = missing = 0;

		fprintf (stdout, "  |--- ");

		do
		{
			name     = package->required[i].name;
			op       = package->required[i].op;
			version  = package->required[i].version;
			next     = package->required[i].OR_next; /* 0 or 1 */
			missing += package->required[i].missing; /* 0 or 1 */
			count++;
			i++;

			if (!op[0] || !version[0])
			 op = version = "\b";

			fprintf (stdout, "%s %s %s %s", name, op, version, (next) ? "| " : status[missing == count]);
		}
		while (next);

		/* If there are OR dep (|) print also number of all installed on all alternative */
		if (count > 1)
		 fprintf (stdout, "\b %d/%d]", count - missing, count);
		putchar ('\n');
	}
	
    return;
}

		
/* show package info */
void
show_package_info (pkg_t *packages[], unsigned n_pkgs)
{
    unsigned i;
	int j;

    if (n_pkgs < 1)
     return;

    putchar('\n');

    for (i = 0; i < n_pkgs; i++) {

	fprintf (stdout, "> %s\n", packages[i]->name);

	if (p_fold.desc)
	    fprintf (stdout, "%s",
	    (packages[i]->desc) ? packages[i]->desc : "> No description.\n");
    
    switch (packages[i]->status)
    {
        case PACKAGE_STATUS_NOT_CHECKED:
            break;
        case PACKAGE_STATUS_NOT_INSTALLED:
            fprintf (stdout, "> Status: Not installed.\n");
            break;
        case PACKAGE_STATUS_INSTALLED:
            fprintf (stdout, "> Status: Installed.\n");
            break;
        default:
            fprintf (stdout, "> Status: Installed (%s).\n", packages[i]->installed);
            break;
    }
        
	fprintf (stdout, "> Location: [%s] %s\n",
	    REPOS[packages[i]->N_REPO].name, packages[i]->location);

	if (p_fold.size_c) {
	    if (packages[i]->size_c > 0)
		 fprintf (stdout, "> Size Compressed: %d KB\n", packages[i]->size_c);
	    else
		 fprintf (stdout, "> Size Compressed: not specified.\n");
	}

	if (p_fold.size_u)
	{
	    if (packages[i]->size_u > 0)
		 fprintf (stdout, "> Size Decompressed: %d KB\n", packages[i]->size_u);
	    else
		 fprintf (stdout, "> Size Decompressed: not specificed.\n");
	}

	if (p_fold.conflict)
	{
		fprintf (stdout, "> Package conflict with: %s", strfeature (packages[i]->nconflicts));
		for (j = 0; j < packages[i]->nconflicts; j++)
		{
			fprintf (stdout, "    >>> %s\n", packages[i]->conflicts[j].name);
	    }
	}

	if (p_fold.suggest)
	{
	    fprintf (stdout, "> Packages suggest: %s", strfeature (packages[i]->nsuggests));
		for (j = 0; j < packages[i]->nsuggests; j++)
		{
			fprintf (stdout, "    >>> %s\n", packages[i]->suggests[j].name);
	    }
	}

	if (p_fold.req)
	{
		show_packages_required (packages[i]);
    }
	
	if (i != (unsigned) n_pkgs - 1)
	 putchar('\n');

	}

    return;
}

/* show missing dependency for each packages required and downloaded */
void
show_missing_req (pkg_t *packages[], unsigned n_pkgs)
{
    unsigned i;
	int j;
	char *name, *op, *version;

    putchar('\n');

	for (i = 0; i < n_pkgs; i++)
    {
		if (have_missing_req (packages[i]))
		{
			fprintf (stdout, "Missing dependency of %s:\n", packages[i]->name);

			for (j = 0; j < packages[i]->nrequired; j++)
			{
				if (packages[i]->required[j].missing)
				{
					name    = packages[i]->required[j].name;
					op      = packages[i]->required[j].op;
					version = packages[i]->required[j].version;

					fprintf (stdout, ">>>  %s", name);

					if (op && op[0] && version)
					{
						fprintf (stdout, " %s %s", op, version);
    				}
					putchar ('\n');
				}
			}
		}
	}
	
    putchar('\n');
    return;

}

/* print all packages required not installed. */
void
make_missing_req_list (pkg_t *packages[], unsigned packages_found)
{
    dlist *missingreq = NULL, *current;
    unsigned i;
	int j;
    char *name, *op, *version, dep[WORDSIZE0];

    /* for each package ... */
    for (i = 0; i < packages_found; i++)
	{
        if (!have_missing_req (packages[i]))
		{
			continue;
		}

		/* for each missing package required ... */
	    for (j = 0; j < packages[i]->nrequired; j++)
	    {
			if (!packages[i]->required[j].missing)
			 continue;

			name    = packages[i]->required[j].name;
			op      = packages[i]->required[j].op;
			version = packages[i]->required[j].version;
			
			if (op && op[0] && version)
			 snprintf (dep, WORDSIZE, "%s %s %s", name, op, version);
            else
			 snprintf (dep, WORDSIZE, "%s", name);
             
	        /* verify if dependency already is in list */
	        if (dlist_check (missingreq, dep) == 0)
        	{
	            dlist_add (&missingreq, xstrdup (dep));
            }
	    }
    }
	
    /* print result */
    if (missingreq)
	{
		fprintf (stdout,
		"+----------------------------------+\n"
		"| Total missing required packages, %d:\n"
		"| ", dlist_count (missingreq));

		for (i = 1, current = missingreq; current->next; current = current->next, i++)
		{
		    fprintf (stdout, "%s,%s ", current->s, (!(i % 3)) ? "\n|" : "");
        }
		
		fprintf (stdout, "%s.\n"
		 "+----------------------------------+\n", current->s);
	}
	
	dlist_free (&missingreq);

	return ;
}


/* Split package `pkg' struct (name, version, arch and build) and save tokens
 * to `data' package struct type.
 */
bool
split_pkg (const char *pkg, pkg_struct *pstruct)
{
    char name[PACKAGE_SIZE + 1], *ptr = NULL;
    int i = 0, len = strlen (pkg);
    unsigned t = 0;

    /* Normally a package containe 4 token: name, version, arch and build.
     * Each token is '-' separated.
     * Our package must have at least 3 '-' (name-version-arch-build) otherwise
     * we consider it as abnormal package, ignore and print a warning.
     */
    const unsigned short ntoken = 3;

    strncpy (name, pkg, PACKAGE_SIZE);
    while (i < len) {
        if (name[i++] == '-' && name[i] != '-')
         t++;
    }
    if (t < ntoken) {
        printfw ("Warning: package `%s' isn't standard. Skipping.\n", pkg);
        return true;
    }

    len -= 4; /* ".tgz" length */
    if (len < 0) {
        printfw ("Warning: unexpected error parsing package `%s'. Skipping.\n", pkg);
        return true;
    }
    
    if (strcasecmp (name + len, ".tgz") == 0)
     name[len] = 0x00;


    ptr = strrchr (name, '-');
    if (strlen (ptr) >= BUILDSIZE) {
        printfw ("Warning: build token of package `%s' is too long. Skipping.\n", pkg);
        return true;
    }
    strncpy (pstruct->build, ptr + 1, BUILDSIZE);
    *ptr = 0x00;

    ptr = strrchr (name, '-');
    if (strlen (ptr) >= ARCHSIZE) {
        printfw ("Warning: arch token of package `%s' is too long. Skipping.\n", pkg);
        return true;
    }
    strncpy (pstruct->arch, ptr + 1, ARCHSIZE);
    *ptr = 0x00;

    ptr = strrchr (name, '-');
    if (strlen (ptr) >= VERSIONSIZE) {
        printfw ("Warning: version token of package `%s' is too long. Skipping.\n", pkg);
        return true;
    }
    strncpy (pstruct->version, ptr + 1, VERSIONSIZE);
    *ptr = 0x00;

    if (strlen (name) >= NAMESIZE) {
        printfw ("Warning: name token of package `%s' is too long. Skipping.\n", pkg);
        return true;
    }
    strncpy (pstruct->name, name, NAMESIZE);
    
    return false;
}

/* Print current package required or suggested (list[index]) and all alternative. */ 
static void
print_required_needed (int flag, dep_t *list, int index, const char *by)
{
	int i = index;
	bool next;
	char *name, *op, *version;

	if (flag == DEP_T_REQUIRED)
	 fprintf (stdout, ">> Required ");
	else
	if (flag == DEP_T_SUGGESTED)
	 fprintf (stdout, ">> Suggested ");
	else
	slassert (NULL);
	
	do
	{
		name    = list[i].name;
		op      = list[i].op;
		version = list[i].version;
		next    = list[i].OR_next;

		if (!op || !op[0] || !version)
		 op = version = "\b";

		fprintf (stdout, "%s %s %s %s", name, op, version, (next) ? "or " : "");
		i++;
	}
	while (next);

	fprintf (stdout, "[by %s]\n", by);
	return;
}

/* Print current missing package required or suggested (list[index]) and all alternative. */ 
static void
print_required_missing (int flag, dep_t *list, int index, const char *by)
{
	const char *type[] = { "required", "suggested" };
	char *name, *op, *version;
	int i = index;
	bool next;
	
	slassert (flag == DEP_T_REQUIRED_MISS || flag == DEP_T_SUGGESTED_MISS);

	fprintf (stdout, "** Warning: missing ");

	do
	{
		name    = list[i].name;
		op      = list[i].op;
		version = list[i].version;
		next    = list[i].OR_next;

		if (!op || !op[0] || !version)
		 op = version = "\b";

		fprintf (stdout, "%s %s %s %s", name, op, version, (next) ? "or " : "");
		i++;
	}
	while (next);

	fprintf (stdout, "%s by %s\n", type[flag != DEP_T_REQUIRED_MISS], by);	
	return;
}

/* Search a package required or suggested, checking version before add
 * to list of packages available. */
static pkg_l *
search_dep (dep_t *dep)
{
	pkg_l *prev, *list = NULL, *current = search (MATCH_EXACTLY_NAME, dep->name);

	while (current)
	{		
		if (required_ok (dep, current->p))
		{
			/* Version ok, add it to list... */
			pkgl_add (&list, current->p);
		}
		else
		{
			pkg_t_free (&current->p);
		}

		prev = current;
		current = current->next;
		free (prev);
	}

	return list;
}

/* Make choose a package from `n' element available from `list'.
 * Return package choosed.
 */
static pkg_t *
choose_dep (pkg_t *list[], unsigned n, bool verbose)
{
	unsigned i = 0, j, v;
	char *name, c;

	/* For each package available... */
	while (i < n)
	{
		j = i + 1;

		name = list[i]->pstruct.name;

		do
		{
			if (verbose && j < n && (v = j) == (i + 1) && strcmp (name, list[v]->pstruct.name) == 0)
			{
				/* First iteration, print all same packages with different version. */
				fprintf (stdout, "Found different version of package %s:\n", name);
				fprintf (stdout, " --> %s\n", list[i]->name);

				do
				{
					fprintf (stdout, " --> %s\n", list[v++]->name);
				}
				while (v < n && strcmp (name, list[v]->pstruct.name) == 0);
			}
		
			if (opt.force)
			{
                if ((i + 1) < n && !strcmp (name, list[i + 1]->pstruct.name))
                {
                    printfv ("Will be used %s\n", list[i]->name);
                }
				return list[i];
			}

			fprintf (stdout, "Download %s %s ? [y/n] ", list[i]->name, pkg_type (list[i]));
			fflush (stdout);
			
			if ((c = getc (stdin)) != '\n')
			 clrbuff ();
			 
			if (c == 'y' || c == 'Y')
			{
				return list[i];
			}			

			i++;
		}
		while (i < n && strcmp (name, list[i]->pstruct.name) == 0);
	}

	return NULL;
}

static bool
dep_already_added (choose_dep_t *data, dep_t *deplist, unsigned index)
{
	unsigned i = index, j;
	pkg_l *current = data->added; /* packages required or suggested added for now */
	pkg_t **pdown = data->next; /* packages added from download menu */
	unsigned ndown = data->nnext; /* number of packages added from download menu */

	j = i;
	do
	{
		/* Search current dep and alternative in download list */
		if (pkg_t_check (deplist[j].name, pdown, ndown, MATCH_EXACTLY_NAME))
		{
			return true;
		}
	}
	while (deplist[j++].OR_next);

	while (current)
	{
		j = i;

		/* Search current dep and alternative in dependencies list */
		do
		{
			if (required_ok (&deplist[j], current->p))
			{
                /* dependency already satisfacted */
                return true;
			}
		}
		while (deplist[j++].OR_next);
		
		current = current->next;
	}

	return false;
}

/* Move index to next dep, skipping also current dep alternative */
static int
dep_next (dep_t *deplist, int *index)
{
	if (*index < 0)
	 return -1;

	while (deplist[*index].OR_next)
	{
		++*index;
	}
	++*index;
	return *index;
}

static bool
curr_or_next_dep_inst (dep_t *dep, unsigned ndep, unsigned i)
{
    while (i < ndep && dep[i].missing)
    {
        if (!dep[i].OR_next)
        {
            return false;
        }

        i++;
    }

    return true;
}

void
choice_dep (choose_dep_t *data, pkg_t *package, int type)
{
	dep_t *group;
	int i, ngroup;
	pkg_t **flist = NULL, *choosed;
	unsigned nflist;
	pkg_l *found = NULL;
	int j, f;
	bool verbose = (!opt.force || opt.verbose);
	
	switch (type)
	{
		case DEP_T_REQUIRED:
			group  = package->required;
			ngroup = package->nrequired;
			break;
		case DEP_T_SUGGESTED:
			group  = package->suggests;
			ngroup = package->nsuggests;
			break;
		default:
			slassert (NULL);
	}

	i = 0x00;

	while (i < ngroup)
	{
		if (curr_or_next_dep_inst (group, ngroup, i) || dep_already_added (data, group, i))
		{
			dep_next (group, &i);
			continue;
		}

		j = i;
		do
		{
            pkgl_join (&found, search_dep (&group[j]));
		}
		while (group[j++].OR_next);

		if (found == NULL)
		{
			if (opt.warn)
			{
				f = (type == DEP_T_REQUIRED) ? DEP_T_REQUIRED_MISS : DEP_T_SUGGESTED_MISS;
				print_required_missing (f, group, i, package->pstruct.name);
			}
		}
		else
		{
			if (verbose)
			 print_required_needed (type, group, i, package->name);			

			flist = pkgl2pkgt (found, &nflist);
			found = NULL;

			sort_pkg (&flist, &nflist);

			pkgl_add (&data->added, (choosed = choose_dep (flist, nflist, verbose)));

			while (nflist--)
			 if (choosed != flist[nflist])
			  pkg_t_free (&flist[nflist]);
			free (flist);

			if (choosed)
			{
				choice_dep (data, choosed, DEP_T_REQUIRED);
				choice_dep (data, choosed, DEP_T_SUGGESTED);
			}
		}
	
		dep_next (group, &i);
	}
    
    return;
}


/* Obtain installed packages compressed and uncompressed size. */
static int
installed_packages_sz (const char *pkg, unsigned *compressed, unsigned *uncompressed)
{
	const unsigned maxline       = 5; /* We parse max 5 line */
	const char compressedstr  [] = "COMPRESSED PACKAGE SIZE:";
	const char uncompressedstr[] = "UNCOMPRESSED PACKAGE SIZE:";
	const unsigned short compressedlen      = 24;
	const unsigned short uncompressedlen    = 26;
	
	
	FILE *fd;
	char buffer[BUFFSIZE0], line[BUFFSIZE0];
	unsigned i;
	
	snprintf (buffer,BUFFSIZE, "%s/%s", PKGDIR, pkg);
	if (!(fd = fopen (buffer, "r")))
	 return -1;
	
	*compressed   = 0x00;
	*uncompressed = 0x00;
	
	for (i = 0; (!*compressed || !*uncompressed) && i < maxline; i++)
	{
		if (!fgets (line, BUFFSIZE, fd)) break;
		
		if (strncmp (line, compressedstr, compressedlen) == 0)
		{
			*compressed = atoi (line + compressedlen);
		}
		else
		if (strncmp (line, uncompressedstr, uncompressedlen) == 0)
		{
			*uncompressed = atoi (line + uncompressedlen);
		}
	}
	
	fclose (fd);
	return (*compressed > 0 && *uncompressed > 0) ? 0 : -1;
}
	
/* show packages installed */
void
installed_packages (const char *name)
{
    unsigned i, inst = 0, compressed = 0, uncompressed = 0;
    dlist *installed;
    char buffer[BUFFSIZE0];
    regex_t preg;
    int cflags = REG_EXTENDED | REG_NOSUB;
    
    if (!name)
     fprintf (stdout, "All packages installed: ");
    else
     fprintf (stdout, "Installed packages \"%s\": ", name);

    fflush (stdout);
    
    if (opt.case_insensitive)
     cflags |= REG_ICASE;

    if (name && opt.use_regex)
     xregcomp (&preg, name, cflags);
    
    for (installed = NULL, i = 0; i < nginst; i++)
    {
        if (!name ||
         (opt.use_regex  && !regexec (&preg, ginst[i].name, 0, NULL, 0)) ||
         (!opt.use_regex && xstrstr (ginst[i].name, name)))
        {		    
            if (opt.verbose
             && !installed_packages_sz (ginst[i].name, &compressed, &uncompressed))
            {
                snprintf (buffer, BUFFSIZE, "%s [%u KB -> %u KB]",
                    ginst[i].name, compressed, uncompressed);
            }
            else
		    {
                snprintf (buffer, BUFFSIZE, "%s", ginst[i].name);
            }
            dlist_add (&installed, xstrdup (buffer));
            inst++;
        }
	}

    if (!inst)
     fprintf (stdout, "nothing.\n");
    else
    {
        fprintf (stdout, "%u\n\n", inst);
        dlist_print (installed, " -> ", "\n");
        dlist_free (&installed);
    }

    if (name && opt.use_regex)
     regfree (&preg);

    return;
}


dlist *
pkglist_official (void)
{
    dlist *pkglist = NULL, *pkgdata = NULL, *curr = NULL;
    unsigned origin = 0x00;
    branches branch;
    char path[BUFFSIZE0], *p1, *p2;

    /* Search official mirror in config file */
    while (origin < N_REPOS)
    {
        if (REPOS[origin].SLACKWARE)
        {
            break;
        }
        origin++;
    }

    if (origin >= N_REPOS)
    {
        return NULL;
    }

    /* Read data from all mirror branch, packages, patches and extra. */
    for (branch = 0; branch < BRANCHES; branch++)
    {
        snprintf (path, BUFFSIZE, "%s", make_rpath (origin, branch, PACKAGES));

        if (!file_exist (path, NULL, true))
        {
            /* Missing a packages list */
            dlist_free (&pkglist);
            dlist_free (&pkgdata);
            return NULL;
        }

        /* Load all packages for current branch */
        if (search_pkg (&pkgdata, MATCH_ALL_NAME, path, NULL) > 0)
        {
            curr = pkgdata;

            while (curr)
            {
                p1 = curr->s + strlen (PKG_NAME); /* point after 'PACKAGE NAME:' */

                if ((p2 = strchr (p1, '\n')))
                {
                    *p2 = 0x00; /* close string, we ignore next data */
                }

                movestrlim (&p1, " \t\n:", 2);

                /* Add package name to list with NO extension */
                if ((p2 = strcasestr (p1, ".txz\0")) || (p2 = strcasestr (p1, ".tgz\0")))
                {
                    *p2 = 0x00;
                }
                dlist_add (&pkglist, xstrdup (p1));

                curr = curr->next;
            }
            dlist_free (&pkgdata);
        }
    }
        
    return pkglist;
}

/* Search non-slackware packages. 
 * for each package installed, search it in slackware packages data. 
 */
void
unofficial_packages (const char *name)
{
    unsigned i = 0, ch = 0;
    dlist *official = NULL, *unofficial = NULL;
    regex_t preg;
    int cflags = REG_EXTENDED | REG_NOSUB;
    
    official = pkglist_official ();
    if (official == NULL)
    {
        fprintf (stderr,
            "\nMissing or incomplete slackware packages list."
            "\nTry to update or fix your slackyd.conf.\n");
        return ;
    }
        
    if (name && opt.use_regex) {
        if (opt.case_insensitive)
         cflags |= REG_ICASE;
        xregcomp (&preg, name, cflags);
    }

    for (i = 0; i < nginst; i++)
    {

        /* if name is non null we wont test just installed packages
         * containing `name'.
         */
         if ((name && opt.use_regex  && regexec (&preg, ginst[i].name, 0, NULL, 0))
          || (name && !opt.use_regex && !xstrstr (ginst[i].name, name)))
         {
              continue;
         }

         printfv ("Checking %s: ", ginst[i].name);
        
         /* search current installed package in all official packages loaded before */
         if (dlist_check (official, ginst[i].name) == 0)
         {
             dlist_add (&unofficial, xstrdup (ginst[i].name));
             printfv ("unofficial.\n");
         }
         else
         {
             printfv ("official.\n");
         }

         ch++;
    }

    dlist_free (&official);

    if (name && opt.use_regex)
     regfree (&preg);
    
    printfv ("\n");

    if (!name)
     fprintf (stdout, "Unofficial packages: ");
    else
     fprintf (stdout, "Unofficial packages \"%s\": ", name);
    fflush (stdout);


    /* print result */
    switch (ch)
    {
        case 0:
            if (name)
             fprintf (stdout, "nothing installed.\n");
            else
             _error (1, "error.\n\n"
               "No packages found.\n"
               "Try to update packages list.\n\n");
             break;
        default:
            if (unofficial == NULL)
             fprintf (stdout, "nothing on %u installed.\n", ch);
            else
            {
                fprintf (stdout, "%u\n\n", dlist_count (unofficial));
                dlist_print (unofficial, " -> ", "\n");
            }
            break;
    }

    dlist_free (&unofficial);
    
    return ;
}

/* Search and print obsolete packages, installed
 * but missing from our repositories */
void
obsolete_packages (const char *name)
{
    pkg_t **packages;
    unsigned i, npackages, matched;
    char *ptr;
    dlist *obsolete;
    regex_t preg;
    int cflags = REG_EXTENDED | REG_NOSUB;
    const bool saveopt = opt.blacklist;

    if (name && opt.use_regex) {
        if (opt.case_insensitive)
         cflags |= REG_ICASE;
        xregcomp (&preg, name, cflags);
    }

    packages_list_check (false, PKGLIST_CHECK_QUIT_ALWAIS);
        
    /* disable blacklist */
    opt.blacklist = false;

    /* load all packages available */
    packages = pkgl2pkgt (search (MATCH_ALL_NAME, NULL), &npackages);

    /* remove extension */
    for (i = 0; i < npackages; i++)
    {
        if ((ptr = strcasestr (packages[i]->name, ".txz\0"))
         || (ptr = strcasestr (packages[i]->name, ".tgz\0")))
        {
            *ptr = 0x00;
        }
    }
    
    opt.blacklist = saveopt;
    
    /* for each package installed ... */
    obsolete = NULL;
    matched  = 0;
    for (i = 0; npackages > 0 && i < nginst; i++)
    {
        /* if name is non null we wont test just installed packages
         * containing `name'.
         */
        if ((name && opt.use_regex  && regexec (&preg, ginst[i].name, 0, NULL, 0))
         || (name && !opt.use_regex && !xstrstr (ginst[i].name, name)))
        {
            continue;
        }
          
        matched++;

        printfv ("Checking %s: ", ginst[i].name);
        
        /* Search current installed packages on all packages available list */
        if (!pkg_t_check (ginst[i].name, packages, npackages, MATCH_EXACTLY_PACKAGE))
        {
            printfv ("obsolete.\n");
            dlist_add (&obsolete, xstrdup (ginst[i].name));
        }
        else
        {
            printfv ("available.\n");
        }
    }

    if (name && opt.use_regex)
     regfree (&preg);
    pkg_t_free_all (&packages, npackages);


    printfv ("\n");

    if (!name)
     fprintf (stdout, "Obsolete packages: ");
    else
     fprintf (stdout, "Obsolete packages \"%s\": ", name);

    fflush (stdout);

    switch ((i = dlist_count (obsolete)))
    {
        case 0:
            if (matched > 0)
             fprintf (stdout, "nothing.\n");
            else
             fprintf (stdout, (name) ? "nothing installed.\n" : "unexpected error.\n");
            break;
        default:
            fprintf (stdout, "%u\n\n", i);
            dlist_print (obsolete, " -> ", "\n");
            dlist_free (&obsolete);
            break;
    }   

    return;
}


/* show available packages blacklisted by config file */
void
blacklisted_packages (const char *pkgname)
{
    pkg_t **packages = NULL;
    unsigned i, n = 0x00;
    int sflags;

    if (opt.nblacklisted == 0) {
        fprintf (stderr, "No packages blacklisted in config file.\n");
        return ;
    }

    packages_list_check (true, PKGLIST_CHECK_QUIT_ON_ALL);

    /* force blacklist disable, otherwise
     * packages blacklisted will not saved.
     */
    opt.blacklist = false;

    if (!pkgname)
     fprintf (stdout, "Blacklisted packages: ");
    else
     fprintf (stdout, "Blacklisted packages `%s': ", pkgname);
    fflush (stdout);

    sflags = (!pkgname || !opt.use_regex) ? MATCH_ALL_NAME_BLACK : MATCH_ALL_NAME_BLACK_REG;

    packages = pkgl2pkgt (search (sflags, pkgname), &n);

    if (!n)
    {
        fprintf (stdout, "nothing.\n");
        return ;
    }

    printf ("%u\n\n", n);
    
    for (i = 0; i < n; i++)
    {
        if (packages[i]->blacklisted)
         fprintf (stdout, " --> %s\n", packages[i]->name);
        pkg_t_free (&packages[i]);
    }
    fflush (stdout);
    free (packages);

    return ;
}


void
replaceable_packages (const char *pkgname)
{
    char path[BUFFSIZE0];
    dlist *pkgdata = NULL;
    pkg_t **packages = NULL;
    unsigned npackages = 0, i, j, r, rprint = 0;
    pkg_l *pkgtmp = NULL, *current = NULL, *replaceable = NULL, *rtmp = NULL;
    regex_t preg;
    int cflags = REG_EXTENDED | REG_NOSUB;
    
    printf ("Loading packages: ");
    fflush (stdout);

    if (pkgname && opt.use_regex) {
        if (opt.case_insensitive)
         cflags |= REG_ICASE;
        xregcomp (&preg, pkgname, cflags);
    }

    /* check official mirror in config file */
    for (r = 0; r < N_REPOS && ! REPOS[r].SLACKWARE; r++)
    ;
    if (r >= N_REPOS)
    {
        fprintf (stderr,
            "\nNo official repository in your slackyd.conf.\n"
            "Please fix it.\n");
        return ;
    }

    /* Load all slackware packages available */
    j = 0;
    while (j < BRANCHES)
    {
        /* official brach `j' packages list path */
        snprintf (path, BUFFSIZE, "%s", make_rpath (r, j, PACKAGES));

        if (!file_exist (path, NULL, true))
        {
            fprintf (stderr, "Broken slackware packages list. Have you update ?\n");
            pkgl_free (&pkgtmp);
            return ;
        }

        /* load all packages for current branch */
        if (search_pkg (&pkgdata, MATCH_ALL_NAME, path, NULL) > 0)
        {
            pkgl_join (&pkgtmp, save_pkg_data (pkgdata, r, j));
            dlist_free (&pkgdata);
        }

        j++;
    }

    printf ("done.\n");
    printf ("Replaceable packages: ");
    fflush (stdout);

    /* For each installed packages check for it origin */
    for (i = 0; i < nginst; i++)
    {
        if ((pkgname && opt.use_regex  && regexec (&preg, ginst[i].name, 0, NULL, 0))
         || (pkgname && !opt.use_regex && !xstrstr (ginst[i].name, pkgname)))
        {
            continue;
        }

        /* Verify if current installed packages isn't official */
        if (!pkgl_check (ginst[i].name, pkgtmp, MATCH_EXACTLY_PACKAGE))
        {
            /* first print on verbose mode */
            printfv ("%s -> %s: ", (!rprint) ? "\n\n" : "", ginst[i].name);

            current = pkgtmp;

            /* Check slackware packages to replace current unofficial */
            while (current)
            {
                if (!strcasecmp (ginst[i].pstruct.name, current->p->pstruct.name))
                {
                    pkgl_add (&rtmp, pkg_t_dup (current->p));
                }
                current = current->next;
            }

            if (rtmp == NULL)
            {
                if (opt.verbose) {
                    rprint++;
                }
                printfv ("nothing to do.\n");
            }
            else
            {
                /* Print official alternatives found for current installed package */
                if (!opt.verbose) {
                    printf ("%s -> %s: ", (!rprint) ? "\n\n" : "", ginst[i].name);
                }
                pkgl_print (rtmp, "", ", ");
                printf ("\n");

                /* Append to replaceable packages list current packages */
                pkgl_join (&replaceable, rtmp);
                rtmp = NULL;
                rprint++;
            }
        }
    }

    if (pkgname && opt.use_regex) {
        regfree (&preg);
    }

    pkgl_free (&pkgtmp);

    pkg_t_free_all (&packages, npackages);

    if (replaceable == NULL)
    {
        if (!opt.verbose) {
            printf ("nothing.\n");
        }
        return;
    }

    packages = pkgl2pkgt (replaceable, &npackages);

    sort_pkg (&packages, &npackages);

    get (&packages, &npackages);

    pkg_t_free_all (&packages, npackages);

    return;
}
    

static rstat_t
make_rstat (unsigned index, pkg_t **packages, unsigned n)
{
    unsigned i;
    rstat_t s;

    memset (&s, 0, sizeof (s));

    s.slackware = REPOS[index].SLACKWARE;
    snprintf (s.rname, BUFFSIZE, REPOS[index].name);
    snprintf (s.raddr, BUFFSIZE, REPOS[index].hostname);

    for (i = 0; i < n; i++) {

        if (packages[i]->N_REPO != index)
         continue;

        switch ((int) packages[i]->branch) {
            case _PACKAGES:
                s.n_packages++;
                s.packages_sz[RS_COMPRESSED]   += packages[i]->size_c;
                s.packages_sz[RS_UNCOMPRESSED] += packages[i]->size_u;
                break;
            case _PATCHES:
                s.n_patches++;
                s.patches_sz[RS_COMPRESSED]   += packages[i]->size_c;
                s.patches_sz[RS_UNCOMPRESSED] += packages[i]->size_u;
                break;
            case _EXTRA:
                s.n_extra++;
                s.extra_sz[RS_COMPRESSED]   += packages[i]->size_c;
                s.extra_sz[RS_UNCOMPRESSED] += packages[i]->size_u;
                break;
            default:
                slassert (NULL);
                break;
         }
         
     }

     s.n_total = s.n_packages + s.n_patches + s.n_extra;
     s.total_sz[RS_COMPRESSED] =
        s.packages_sz[RS_COMPRESSED] +
        s.patches_sz [RS_COMPRESSED] +
        s.extra_sz   [RS_COMPRESSED];
     s.total_sz[RS_UNCOMPRESSED] =
        s.packages_sz[RS_UNCOMPRESSED] +
        s.patches_sz [RS_UNCOMPRESSED] +
        s.extra_sz   [RS_UNCOMPRESSED];
        
     return s;
 }

static void
print_rstat (rstat_t s)
{
    fprintf (stdout,
    "Stats of %s [%s]:\n", s.rname, s.raddr);
    fprintf (stdout,
    "   Official: %s\n", (s.slackware) ? "yes" : "no");
    fprintf (stdout,
    "   Packages: [%u]\n", s.n_packages);

    if (s.n_packages > 0)
    fprintf (stdout,
    "      Compressed size  : [%u MB]\n"
    "      Uncompressed size: [%u MB]\n",
    s.packages_sz[RS_COMPRESSED]   / 1024,
    s.packages_sz[RS_UNCOMPRESSED] / 1024);
    
    if (s.slackware) {
        
    fprintf (stdout,
    "   Patches : [%u]\n", s.n_patches);
    if (s.n_patches > 0)
    fprintf (stdout,
    "      Compressed size  : [%u MB]\n"
    "      Uncompressed size: [%u MB]\n",
    s.patches_sz [RS_COMPRESSED]   / 1024,
    s.patches_sz [RS_UNCOMPRESSED] / 1024);

    fprintf (stdout,
    "   Extra   : [%u]\n", s.n_extra);
    if (s.n_extra > 0)
    fprintf (stdout,
    "      Compressed size  : [%u MB]\n"
    "      Uncompressed size: [%u MB]\n",
    s.extra_sz [RS_COMPRESSED]   / 1024,
    s.extra_sz [RS_UNCOMPRESSED] / 1024);
    
     fprintf (stdout,
    "   All     : [%u]\n", s.n_total);

    if (s.n_total > 0)
    fprintf (stdout,
    "      Compressed size  : [%u MB]\n"
    "      Uncompressed size: [%u MB]\n",
    s.total_sz[RS_COMPRESSED]   / 1024,
    s.total_sz[RS_UNCOMPRESSED] / 1024);

    }

    putchar ('\n');

    return;
}
 
int
rstat (void)
{
    unsigned long i, total = 0, total_sz[2] = { 0, 0 };
    unsigned npackages, blacklisted = 0;
    bool slackware = false;
    pkg_t **packages = NULL;
    rstat_t stats;

    packages_list_check (true, PKGLIST_CHECK_QUIT_ON_ALL);

    /* force to enable black list */
    opt.blacklist = true;

    fprintf (stdout, "Making repositories statistics.\n");
    
    fprintf (stdout, "Reading packages data: ");
    fflush (stdout);    

    packages = pkgl2pkgt (search (MATCH_ALL_NAME, NULL), &npackages);

    if (!npackages) {
         fprintf (stderr, "failed. Try to update.\n");
         return EXIT_FAILURE;
    }

    /* count blacklisted */
    for (i = 0; i < npackages; i++)
     if (packages[i]->blacklisted)
      blacklisted++;
    
    fprintf (stdout, "ok.\n");

    fprintf (stdout,
    "-------------------------------\n");

    for (i = 0; i < N_REPOS; i++) {

        if (REPOS[i].SLACKWARE && slackware)
         continue;
         
        memset ((void *) &stats, 0, sizeof (rstat_t));
        stats = make_rstat (i, packages, npackages);

        total += stats.n_total;
        total_sz [RS_COMPRESSED]   += stats.total_sz[RS_COMPRESSED];
        total_sz [RS_UNCOMPRESSED] += stats.total_sz[RS_UNCOMPRESSED];
        
        print_rstat (stats);
    
        if (REPOS[i].SLACKWARE)
         slackware = true;
     }

    fprintf (stdout,
    "-------------------------------\n"
    "All packages: %lu", total);

    if (blacklisted > 0)
     fprintf (stdout, " (%u blacklisted)", blacklisted);
     
    fprintf (stdout, ".\n"
    "    Compressed size  : [%lu MB]\n"
    "    Uncompressed size: [%lu MB]\n",
    total_sz[RS_COMPRESSED] / 1024, total_sz[RS_UNCOMPRESSED] / 1024);
    
    pkg_t_free_all (&packages, npackages);
    
    return EXIT_SUCCESS;
 }


static int
pkg_occ (pkg_t *packages[], unsigned npackages, const char *name, unsigned *pindex)
{
    int rval = 0;
    unsigned n, l;
    char *pkgname;

    l = strlen (name);
        
    for (n = 0; n < npackages; n++)
    {
        pkgname = packages[n]->name;
        
        if (!strncmp (name, pkgname, l) &&
            (!strcmp (pkgname + l, ".txz\0") || !strcmp (pkgname + l, ".tgz\0")))
        {
            *pindex = n;
            rval++;
        }
    }
    
    if (rval == 1 && packages[*pindex]->nrequired == FEATURE_UNAVAILABLE)
    {
        rval = FEATURE_UNAVAILABLE;
    }
     
    return rval;
}
        
void
search_packager_lib (const char *name)
{
    unsigned i, npackages = 0, ntocheck = 0, pindex = 0;
    unsigned verified = 0, unsupported = 0, orphan = 0;
    int rval, cflags = REG_EXTENDED | REG_NOSUB, sflag;
    regex_t preg;
    pkg_t **packages = NULL, **tocheck = NULL;
    
    choose_dep_t ddata;
	pkg_t **dep    = NULL;
    unsigned ndep  = 0;
    
    memset (&ddata, 0, sizeof (ddata));

	packages_list_check (true, PKGLIST_CHECK_QUIT_ON_ALL);

    if (name)
    {
        sflag = (!opt.use_regex) ? MATCH_ALL_NAME : MATCH_USING_REGEX;
        
        if (is_installed (name, sflag, 0) == PACKAGE_STATUS_NOT_INSTALLED)
        {
            fprintf (stderr, "No packages \"%s\" are installed.\n", name);
            return;
        }
    }

	/* force to disable blacklist */
    opt.blacklist = false;

    fprintf (stdout, "Loading packages data: ");
    fflush (stdout);

    sflag = (!name || !opt.use_regex) ? MATCH_EXACTLY_PACKAGE_INST : MATCH_USING_REGEX;

    packages = pkgl2pkgt (search (sflag, name), &npackages);
    
    if (npackages == 0)
	{
        if (!name)
        {
            _error (1, "error.\n\nNo packages loaded.\n"
                "Try to update or fix your slackyd.conf.\n\n");
        }

        fprintf (stdout, "no packages `%s' available.\n", name);
        return;
    }
    else
    {
        fprintf (stdout, "done.\n");
    }

        
    if (name && opt.use_regex)
    {
        if (opt.case_insensitive)
        {
            cflags |= REG_ICASE;
        }
        xregcomp (&preg, name, cflags);
    }


    fprintf (stdout, "Searching dependencies...\n");
    fflush (stdout);

    for (i = 0; i < nginst; i++)
    {
        
    if ((name && opt.use_regex  && regexec (&preg, ginst[i].name, 0, NULL, 0))
     || (name && !opt.use_regex && !xstrstr (ginst[i].name, name)))
     {
         continue;
     }

	rval = pkg_occ (packages, npackages, ginst[i].name, &pindex);

    switch (rval) {
	    case FEATURE_UNAVAILABLE:
            unsupported++;
            if (opt.verbose && opt.warn) {
                fprintf (stderr, "Warning: no dependencies for `%s'.\n", ginst[i].name);
            }
            break;
        case 0:
            orphan++;
            if (opt.verbose && opt.warn) {
                fprintf (stderr, "Warning: package `%s' not found in repositories.\n", ginst[i].name);
            }
            break;
        case 1:
            verified++;
            if (have_missing_req (packages[pindex])) {
                pkg_t_add (&tocheck, &ntocheck, packages[pindex]);
            }
            else
            if (have_missing_sug (packages[pindex])) {
                pkg_t_add (&tocheck, &ntocheck, packages[pindex]);
            }
            break;
        default:
            if (opt.verbose && opt.warn) {
                fprintf (stderr, "Warning: too packages `%s'. Skipping.\n", ginst[i].name);
            }
            break;
    }
    }

    if (name && opt.use_regex) {
        regfree (&preg);
    }
    pkg_t_free_all (&packages, npackages);


    fprintf (stdout, "\n%u package%s verified, %u unsupported, %u orphan.\n",
        verified, (verified <= 1) ? "" : "s", unsupported, orphan);

    if (ntocheck == 0)
    {
        if (name)
        {
            fprintf (stdout, "\nAll packages \"%s\" checked are ok.\n", name);
        }
        else
        {
            fprintf (stdout, "\nAll packages checked are ok.\n");
        }
        return ;
    }

    for (i = 0; i < ntocheck; i++)
    {
        choice_dep (&ddata, tocheck[i], DEP_T_REQUIRED);
        choice_dep (&ddata, tocheck[i], DEP_T_SUGGESTED);
    }

    pkg_t_free_all (&tocheck, ntocheck);
    
    dep = pkgl2pkgt (ddata.added, &ndep);

	if (!ndep)
    {
        fprintf (stdout, "\nNothing to do.\n");
        return;
    }
    
    putchar ('\n');
    for (i = 0; i < ndep; i++)
    {
       	if (get_pkg (dep[i]) == EXIT_SUCCESS && opt.hash)
       	{
           	verify_md5 (dep[i]);
       	}
    }
	pkg_t_free_all (&dep, ndep);
    	
    return;
}

/* A missing shared library can be found in more packages.
 * Here choose just one.
 * Return a copy of package.
 */
static pkg_t *
double_shared_dep (pkg_l *packages, pkg_l *added)
{
    pkg_l *acurrent = added, *pcurrent = packages;
    char c = 0;

    /* If a missing shared library is contained in a package
     * already choosed and already in download, we here can return
     * without ask nothing.
     */
    while (pcurrent)
    {
        if (pkgl_check (pcurrent->p->pstruct.name, added, MATCH_EXACTLY_NAME))
        {
            return NULL;
        }
        
        pcurrent = pcurrent->next;
    }

    pcurrent = packages;
    acurrent = added;
    
    switch (pkgl_count (packages))
    {
        case 0:
            return NULL;
            break;
        case 1:
            return pkg_t_dup (packages->p);
            break;
        default:
            while (pcurrent)
            {
                if (!opt.force)
                {
                    fprintf (stdout, "Use %s %s ? [y/N] ", pcurrent->p->name, pkg_type (pcurrent->p));
                    fflush (stdout);
                }
                else
                {
                    fprintf (stdout, "Will be used %s\n", pcurrent->p->name);
                }
                
                if (opt.force || (c = getc (stdin)) == 'y' || c == 'y')
                {
                    if (!opt.force)
                     clrbuff ();
                    return pkg_t_dup (pcurrent->p);
                }
                else
                {
                    if (c != '\n') clrbuff ();
                    pcurrent = pcurrent->next;
                }
            }
            break;
    }

    return NULL;
}

int
check_shared_dep (const char *pkg)
{
    int cflags = REG_EXTENDED|REG_NOSUB;
    regex_t preg;
    
    libneed_t *mlibs = NULL;
    unsigned i, j, npkglist = 0, n_mlibs = 0, checked = 0;
    char buffer[BUFFSIZE0] = { 0 }, path[BUFFSIZE0] = { 0 };
    FILE *fd;
    dlist *libpath = NULL, *pkgcur, *objcur;
    pkg_l *tmplist = NULL;
    pkg_t **pkglist = NULL;
    
    /* load paths where search shared libraries.
     */
    process_lib_path (&libpath);
	
    if (pkg && opt.use_regex)
    {
        if (opt.case_insensitive)
         cflags |= REG_ICASE;
        xregcomp (&preg, pkg, cflags);
    }
    
    /* for each package installed ... */
    for (i = 0; i < nginst; i++) {

    if ((pkg && opt.use_regex  && regexec (&preg, ginst[i].name, 0, NULL, 0))
     || (pkg && !opt.use_regex && !xstrstr (ginst[i].name, pkg)))
    {
        continue;
    }
    	
    /* /var/log/packages/<pkgname> */
    snprintf (buffer, BUFFSIZE, "%s/%s", PKGDIR, ginst[i].name);

    fprintf (stdout, "Checking %s: ", ginst[i].name);
    fflush (stdout);

    if (!(fd = fopen (buffer, "r"))) {
		fprintf (stdout, "%s\n", strerror (errno));
        continue;
	}

    /* move stream after package descriptions */
    while (1)
	{
		if (!fgets (buffer, BUFFSIZE, fd) || !strcmp (buffer, "FILE LIST:\n"))
		{
			break;
		}
    }
	
    if (strcmp (buffer, "FILE LIST:\n") != 0)
	{
    	fprintf (stdout, "not pkgtools standard. Skipping.\n");
    	fclose (fd);
    	continue;
	}
    

    /* for each package file */
    while (fgets(buffer, BUFFSIZE, fd))
	{
	 	if (buffer[strlen(buffer) - 1] == '\n')
		{
			buffer[strlen(buffer) - 1] = 0x00;
		}

		snprintf (path, BUFFSIZE, "/%s", buffer);

		check_elf_libs (libpath, path, &mlibs, &n_mlibs, ginst[i].name);
    }
	
	fclose (fd);
    fprintf (stdout, "done.\n");
    checked++;

    } /* end for() */


    dlist_free (&libpath);
    if (pkg && opt.use_regex)
     regfree (&preg);
    
    if (checked == 0)
	{
		slassert (pkg != NULL); /* no packages installed ? */
     	fprintf (stdout, "No packages \"%s\" are installed !\n", pkg);
     	return -1;
    }
	     
    if (n_mlibs == 0)
	{
		if (pkg) {
			fprintf (stdout, "\nAll packages \"%s\" checked are ok !\n", pkg);
		}
		else {
			fprintf (stdout, "\nAll packages are ok !\n");
		}
		return 0;
    }


    fprintf (stdout, "\nFound %u missing dependencies:\n", n_mlibs);

	for (i = 0; i < n_mlibs; i++)
	{
	    fprintf (stdout, "%s required by:\n", mlibs[i].needed);
	    for (pkgcur = mlibs[i].pkgname, objcur = mlibs[i].object;
	         pkgcur && objcur;
	         pkgcur = pkgcur->next, objcur = objcur->next)
        {
            fprintf (stdout, " --> Package: %s (%s)\n", pkgcur->s, objcur->s);
        }
    }

    putchar ('\n');

    /* Search each missing shared object from manifest */
    for (i = 0; i < n_mlibs; i++)
    {
        fprintf (stdout, "Searching %s: ", mlibs[i].needed);
        fflush (stdout);

		j = search_shared_dep (&mlibs[i]);

		if (j > 0) {
			fprintf (stdout, "found %u package%s.\n", j, (j > 1) ? "s" : "");
		}
		else {
			fprintf (stdout, "nothing found.\n");
		}
    }

    /* Use just one packages if same shared object was found
     * in more packages */
    for (i = 0; i < n_mlibs; i++)
    {
        if ((j = pkgl_count (mlibs[i].packages)) > 1)
        {
            fprintf (stdout, "Library %s is contained in %u different packages:\n", mlibs[i].needed, j);
            pkgl_print (mlibs[i].packages, " --> ", "\n");
        }

        /* If a package will be choosed add it to packages list to get */
        pkgl_add (&tmplist, double_shared_dep (mlibs[i].packages, tmplist));

        dlist_free (&mlibs[i].pkgname);
    	dlist_free (&mlibs[i].object);
    	pkgl_free (&mlibs[i].packages);
    }
	free (mlibs);

    if (tmplist == NULL) {
        fprintf (stdout, "\nNothing to do.\n");
        return -1;
    }

    
    pkglist = pkgl2pkgt (tmplist, &npkglist);

	sort_pkg (&pkglist, &npkglist);

	get (&pkglist, &npkglist);

	pkg_t_free_all (&pkglist, npkglist);

	return EXIT_SUCCESS;
}


/*============================================================*
/ Functions to manage packages sources start                  
/=============================================================*/

/* Return a regex to match pkg_t package using `type' */
static char *
pkgsrc_regex (srcreg_t type, pkg_t *package)
{
    char regex[BUFFSIZE0], name[WORDSIZE0], version[WORDSIZE0];

    strncpy (name, set_regex (package->pstruct.name), WORDSIZE);
    strncpy (version, set_regex (package->pstruct.version), WORDSIZE);
    
    switch (type) {
        case reg_1:
            snprintf (regex, BUFFSIZE, "^\\-.*(\\./source/.*/?%s/)(.*/)?(.*$)", name);
            break;
        case reg_2:
            snprintf (regex, BUFFSIZE, "^\\-.*(\\./.*/%s/%s/src/)(.*/)?(.*$)", name, version);
            break;
        default:
            slassert (NULL);
            break;
        }
        
    return xstrdup (regex);
}    

    
/* Parse `filelist' matching `package' build sources.
 * Match 'filelist` using all regex `srcreg_t' available, see slackyd.h or
 * pkgsrc_regex() above.
 * Return a `pkgsrc_t' structure with build data. `files' and `paths' members
 * will be NULL if no source files was found.
 */
static pkgsrc_t
pkgsrc_files (const char *filelist, pkg_t *package)
{
    FILE *fd = fopen (filelist, "r");
    char line[HUGE0];
    pkgsrc_t srcdata;
    srcreg_t regtype;
    char *regex, *rpath, *fpath, *file;
    regex_t preg;

    regmatch_t matches[4];
    
    srcdata.package = package;
    srcdata.files   = NULL;
    srcdata.paths   = NULL;
    srcdata.rpaths  = NULL;
    
    if (!fd) {
        printfw ("\nWarning: `%s': %s\n\n", filelist, strerror (errno));
        return srcdata;
    }

    /* For each regex available... */
    for (regtype = 0; srcdata.files == NULL && regtype < reg_n; regtype++)
    {
        srcdata.regtype = regtype;
        regex = pkgsrc_regex (regtype, package);
        xregcomp (&preg, regex, REG_EXTENDED | REG_NEWLINE);

        rewind (fd);

        while (fgets (line, HUGE, fd))
        {
            if (strstr (line, package->pstruct.name)
            && !regexec (&preg, line, 4, matches, 0))
            {
                /* Now save splitted line read from filelist and obtain
                 * build file name and path.
                 * For example, if current line is:
                 * "-..... ./source/xx/pkgname/dir1/dir2/slack-desc"
                 * we split as:
                 * rpath: [./source/xx/pkgname/]
                 * fpath: [dir1/dir2/]
                 * file : [slack-desc]
                 *
                 * This to preserve file tree after download :)
                 */
                rpath = strregdup (line, matches[1], 0);
                if ((fpath = strregdup (line, matches[2], 0)) == NULL)
                 fpath = xstrdup ("/");
                file  = strregdup (line, matches[3], 0);
                /* sanity check */
                if (!rpath || !file) {
                    _error (3, "\n\n"
                    "Fatal error parsing build line !\n"
                    "--> [", line, "]\n"
                    "Please report this.\n\n");
                }
                dlist_add (&srcdata.rpaths, rpath);
                dlist_add (&srcdata.paths,  fpath);
                dlist_add (&srcdata.files,  file);
            }
            else
            {
                if (srcdata.files != NULL
                 && strstr (line, package->pstruct.name) == NULL)
                {
                    /* we need of strstr() call here because
                     * we not match directory in filelist (we match "^-rwx..."
                     * but not "^drwx...".
                     */
                    break; /* all build files found and added */
                }
            }
        }
        free (regex);
        regfree (&preg);
    }
    fclose (fd);

    /* Sanity check: for each file must be present each path */
    slassert (dlist_count (srcdata.paths) == dlist_count (srcdata.files));
    slassert (dlist_count (srcdata.paths) == dlist_count (srcdata.rpaths));
    
    return srcdata;
}
        
        


static pkgsrc_t *
pkgsrc_search (pkg_t *packages[], unsigned npackages)
{
    unsigned i, r, b;
    pkgsrc_t *srcdata = (pkgsrc_t *) xmalloc (npackages * sizeof (pkgsrc_t));
    
    for (i = 0; i < npackages; i++)  /* for each package choosed */
    {
        fprintf (stdout, "Searching %s %s build sources: ",
            packages[i]->pstruct.name,
            packages[i]->pstruct.version);
        fflush (stdout);

        r = packages[i]->N_REPO; /* package origin */
        b = _PACKAGES; /* just one filelist for mirror; always PACKAGES */
        srcdata[i] = pkgsrc_files (make_rpath (r, b, FILELIST), packages[i]);

        if (srcdata[i].files == NULL)
         fprintf (stdout, "nothing to do.\n");
        else
         fprintf (stdout, "ok.\n");
    }
    return srcdata;
}
            
        
/* Search packages sources and save data to apposite structure. */
static pkgsrc_t *
pkgsrc (pkg_t **packages[], unsigned *npackages)
{
    unsigned i = 0, j, same;
    char c;
    
    if (*npackages == 0)
     return NULL;

    putchar ('\n');

    while (i < *npackages)
    {

    same = same_pkg (*packages, *npackages, i);

    if (same > 1)
    {
        fprintf (stdout, "Found %u different version of %s:\n", same, (*packages)[i]->pstruct.name);
        for (j = 0; j < same; j++)
         fprintf (stdout, " --> %s\n", (*packages)[i + j]->name);
        if (opt.force)
        {
            fprintf (stdout, "Will be used %s %s\n", (*packages)[i]->name, pkg_type ((*packages)[i]));
            rm_same (packages, npackages, i);
        }
    }

    if (!opt.force)
    do
    {
        fprintf (stdout, "Download %s %s build sources %s ? [y/N] ",
            (*packages)[i]->pstruct.name,
            (*packages)[i]->pstruct.version,
            pkg_type ((*packages)[i]));
	    fflush (stdout);
	    if ((c = getc(stdin)) == 'Y' || c == 'y')
	    {
	        rm_same (packages, npackages, i);
            i++;
            same = 0;
	    }
        else
        {
            --same;
            pkg_t_rm (packages, npackages, i);
        }
	    if (c != '\n')
         clrbuff();
    } while (same > 0 && *npackages > 0);
    else
     i++;

    }

    if (*npackages == 0) {
        fprintf (stdout, "\nNothing was choosed.\n");
        return NULL;
    }

    return pkgsrc_search (*packages, *npackages);
}

/* Try to run slackbuild ... */
static void
pkgsrc_build (pkgsrc_t srcdata)
{
    const char *cache = opt.cache;
    char path[BUFFSIZE0], cwd[BUFFSIZE0], build[WORDSIZE0];

    if (getcwd (cwd, BUFFSIZE) == NULL) {
        fprintf (stdout, "\nError: cannot get cwd: %s\n\n", strerror (errno));
        return ;
    }

    snprintf (path, BUFFSIZE, "%s/src/%s/%s/%s/",
        cache,
        REPOS[srcdata.package->N_REPO].name,
        srcdata.package->pstruct.name,
        srcdata.package->pstruct.version
        );

    if (chdir (path) < 0) {
        fprintf (stdout, "\nError: `%s': %s\n\n", path, strerror (errno));
        return;
    }

    snprintf (build, WORDSIZE, "/bin/sh %s.[Ss]lack[Bb]uild --cleanup",
        srcdata.package->pstruct.name);

    system (build);

    chdir (cwd);
    return;
}
    
int
pkgsrc_get (pkg_t **packages[], unsigned *npackages)
{
    const char *cache = opt.cache;
    pkgsrc_t *srcdata;
    net_t netpolicy;
    protocol_t proto;
    dlist *currents[3];
    unsigned i, r, port;
    
    srcdata = pkgsrc (packages, npackages); /* Can modify number of `npackages' */

    if (*npackages == 0 || srcdata == NULL)
     return -1;
    
    for (i = 0; i < *npackages; i++)
    {
        if (srcdata[i].files == NULL) /* no build files found in filelist */
         continue;

        r = srcdata[i].package->N_REPO; /* package origin */

        fprintf (stdout, "\n"
        "+=================================================================+\n"
        "| %s %s %s build sources from %s \n"
        "+=================================================================+\n",
            (REPOS[r].proto_t == proto_file) ? "Copying" : "Downloading",
            srcdata[i].package->pstruct.name,
            srcdata[i].package->pstruct.version,
            REPOS[r].name);

        /* List splitted paths.
         * Where file path is "./source/xx/prgname/dir1/filename", for example,
         * we can have:
         * current rpaths: [/source/xx/prgname]
         * current paths : [/dir1/]
         * current files : [filename]
         * 
         * This split to preserve directory tree after download ! :)
         */

        currents[0] = srcdata[i].rpaths;
        currents[1] = srcdata[i].paths;
        currents[2] = srcdata[i].files;

        while (currents[0])
        {
            port  = REPOS[r].port; /* mirror port */
            proto = REPOS[r].proto_t; /* mirror protocol */

            init_net_t (&netpolicy, proto, port); /* init network structure */

            netpolicy.savepart   = true;
            netpolicy.overwrite  = false;
            netpolicy.checkstamp = false;
            snprintf (netpolicy.hostname, BUFFSIZE, REPOS[r].hostname);

            snprintf (netpolicy.srcpath, BUFFSIZE, "%s/%s/%s/%s",
                REPOS[r].path,
                currents[0]->s,
                currents[1]->s,
                currents[2]->s);
            snprintf (netpolicy.destpath, BUFFSIZE, "%s/src/%s/%s/%s/%s/%s",
                cache,
                REPOS[r].name,
                srcdata[i].package->pstruct.name,
                srcdata[i].package->pstruct.version,
                currents[1]->s,
                currents[2]->s);
                
            snprintf (netpolicy.msg, BUFFSIZE, " --> %s %s:",
                (REPOS[r].proto_t == proto_file) ? "Copying" : "Downloading",
                currents[2]->s);

            filepath (netpolicy.destpath);
	    if(opt.wget){
		switch (proto) {
		    case proto_http: get_file_over_wget (&netpolicy,true);  break;
		    case proto_ftp:  get_file_over_wget (&netpolicy,false);  break;
		    case proto_file: get_file_over_fs   (&netpolicy);  break;
		default:   slassert (NULL);                               break;
		}
	    }else{
                switch (proto) {
                    case proto_http: get_file_over_http (&netpolicy);  break;
                    case proto_ftp:  get_file_over_ftp  (&netpolicy);  break;
                    case proto_file: get_file_over_fs   (&netpolicy);  break;
                default:   slassert (NULL);                        break;
                }
	    }
                                
            currents[0] = currents[0]->next;
            currents[1] = currents[1]->next;
            currents[2] = currents[2]->next;
        }

        /* Try to build, if is required... */
        if (opt.buildsrc)
         pkgsrc_build (srcdata[i]);        

        /* Not free here `package' pkg_t structure member.
         * It was just 'linked' :) ... Free it later ...
         */
        dlist_free (&srcdata[i].rpaths);
        dlist_free (&srcdata[i].paths);
        dlist_free (&srcdata[i].files);
    }

    free (srcdata);
    return 0;
}

/*============================================================*
/ Functions to manage packages sources end                    *
/=============================================================*/



/* Clean slackyd directory.
 * If `flag' is PURGE_PKG will be removed packages and packages build sources.
 * If `flag' is PURGE_ALL will be removed all in slackyd cache.
 */
int
purge (int flag)
{
    const char *cache = opt.cache;
    char buffer[BUFFSIZE0];

    switch (flag)
    {
        case PURGE_PKG:
            emptydir (cache, "tgz");
            emptydir (cache, "txz");
            emptydir (cache, "part");
            snprintf (buffer, BUFFSIZE, "%s/src", cache);
            rmdir_rf (buffer, true);
            break;

        case PURGE_ALL:
            rmdir_rf (cache, false);
            break;

        default:
            slassert (NULL);
            break;
    }

    return 0;	
}

