/*
 *      update.c
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

/* check for error on bzip2 decompression */
static bool
bzerror (const char *zpath, int bzval)
{
     switch (bzval) {

        case BZ_CONFIG_ERROR:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "Bzip configuration error.\n"
        					 "Your library bzip has been improperly compiled on your platform.\n\n");
        	break;

        case BZ_SEQUENCE_ERROR:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "Bzip sequence error call.\n"
        					 "Please report this.\n\n");
        	break;

        case BZ_PARAM_ERROR:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "A parameter to a function call is out of range or manifestly incorrect.\n"
        					 "Please report this.\n");
        	break;

        case BZ_MEM_ERROR:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "Bzip out of memory.\n\n");
        	break;

        case BZ_DATA_ERROR:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "Bzip data integrity error is detected.\n\n");
        	break;

        case BZ_DATA_ERROR_MAGIC:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "The compressed stream does not start with the correct magic bytes.\n\n");
        	break;

        case BZ_UNEXPECTED_EOF:
        	fprintf (stderr, "\nError on %s bzip decompression:\n", (zpath) ? zpath : "\b");
        	fprintf (stderr, "The compressed file finishes before the logical end of stream is detected.\n\n");
        	break;

        default:
        	return false;
        	break;
    }

    return true;
}
        

/* decompress file `zpath' in file `dest'
 * If `dest' is NULL uncompress file in `zpath' without extension.
 */
static bool
bz_decompress (const char *zpath, char *dest)
{
    char *zdata = NULL, *pdest = (dest) ? dest : xstrdup (zpath), *ptr;
    unsigned zsize;
    char buffer[BUFFSIZE];
    int rval;
    bz_stream zstream;
    FILE *fd;

    if (dest == NULL) {
        if ((ptr = strrchr (pdest, '.')) == NULL) {
            fprintf (stderr, "\nError: %s have no extension.\n", zpath);
            return true;
        }
        *ptr = 0;
    }
    
    /* load compressed data */
    if (!(fd = fopen (zpath, "rb"))) {
        fprintf (stderr, "\n"
        "Cannot decompress %s: %s\n", zpath, strerror (errno));
        return true;
    }
    zsize = get_file_size (fd);
    fdload (&zdata, fd, zsize);
    fclose (fd);
    
    if (zdata == NULL) {
        fprintf (stderr, "Error, %s seem to be void. Operation skipped.\n", zpath);
        return true;
    }
    
    /* initialize structure */
    zstream.total_in_lo32  = 0x00;
    zstream.total_in_hi32  = 0x00;
    zstream.total_out_lo32 = 0x00;
    zstream.total_out_hi32 = 0x00;
    zstream.bzalloc = NULL; /* use default alloc function */
    zstream.bzfree  = NULL; /* use default free function */
    zstream.opaque  = NULL;
    
    zstream.next_in   = zdata;    /* a pointer to compressed data */
    zstream.avail_in  = zsize;    /* compressed data size */
    zstream.next_out  = buffer;   /* temp buffer to save uncompressed data */
    zstream.avail_out = BUFFSIZE; /* temp buffer size */

    if (bzerror (NULL, BZ2_bzDecompressInit (&zstream, 0, 0))) {
        free (zdata);
        return true;
    }    

    remove (pdest);
    /* open location where sava decompressed data */
    if (!(fd = fopen (pdest, "wb"))){
        fprintf (stderr, "\n"
        "Cannot decompress data to %s: %s\n", pdest, strerror (errno));
        BZ2_bzDecompressEnd (&zstream);
        free (zdata);
        return true;
    }

    rval = BZ_OK;
    while ((rval = BZ2_bzDecompress (&zstream)) == BZ_OK) {

        if (fwrite (buffer, 1, BUFFSIZE - zstream.avail_out, fd) !=
            BUFFSIZE - zstream.avail_out)
        {
            fprintf (stderr, "\n"
            "Cannot write decompress data to %s: %s\n", dest, strerror (errno));
            fclose (fd);
            BZ2_bzDecompressEnd (&zstream);
            free (zdata);
            return true;
        }

        /* data saved, we can reuse our buffer */
	    zstream.next_out  = buffer;
	    zstream.avail_out = BUFFSIZE; /* all BUFFSIZE bytes available :P */
	}

    free (zdata);
    if (dest == NULL)
     free (pdest);
    
	if (bzerror (zpath, rval)) {
	    BZ2_bzDecompressEnd (&zstream);
	    return true;
    }
    
    fwrite (buffer, 1, BUFFSIZE - zstream.avail_out, fd);
    fclose (fd);
    
    bzerror (NULL, BZ2_bzDecompressEnd (&zstream));

    return false;
}


/* make update data directories */
static void
update_dir (void)
{
	const char *cache = opt.cache;
    const char *dbranch[BRANCHES] = { "/", "/patches", "/extra" };
	unsigned r = 0;
	char path[BUFFSIZE0];
	bool slackware = false;
	
	for (r = 0; r < N_REPOS; r++) {
		
	if (REPOS[r].SLACKWARE && slackware)
	 continue; /* we use only one official mirror */
		
	/* repository directory */
	snprintf (path, BUFFSIZE, "%s/%s", cache, REPOS[r].name);
	rmkdir (path, 0777);
	
	if (!REPOS[r].SLACKWARE)
	 continue; /* extra repository haven't patches and extra branches */
	
	/* repository patches directory */
	snprintf (path, BUFFSIZE, "%s/%s/%s", cache, REPOS[r].name, dbranch[1]);
	rmkdir (path, 0777);
	/* repository extra directory */
	snprintf (path, BUFFSIZE, "%s/%s/%s", cache, REPOS[r].name, dbranch[2]);
	rmkdir (path, 0777);
	
	if (REPOS[r].SLACKWARE)
	 slackware = true;
	}

	return;
}

/* retrieve a file list of REPOS[index] */
static int
update_get_file (unsigned index, branches branch, const char *file)
{
	net_t netpolicy;
    const char *cache   = opt.cache;
    const char *path    = REPOS[index].path;
    const char *name    = REPOS[index].name;
	const char *host    = REPOS[index].hostname;
    const unsigned port = REPOS[index].port;
    const char *act     = (REPOS[index].proto_t == proto_file) ? "Copying" : "Downloading";
    const char *dfile   = file;
    const bool official = REPOS[index].SLACKWARE;
    const bool manifest = (bool) !strcmp (file, ZMANIFEST);

    if (official && branch == _PACKAGES && manifest)
    {
        /* Fix MANIFEST.bz2 for slackware stable packages branch
         * changing 'MANIFEST.bz2" to "slackware/MANIFEST.bz2".
         * We preserve original file using `dfile' just for
         * file destination path.
         * In other case `file' and `dfile' will be same string !
         */
         file  = (!opt.slackware64) ? SMANIFEST : SMANIFEST64;
         dfile = ZMANIFEST;
     }
    
    init_net_t (&netpolicy, REPOS[index].proto_t, port);

    netpolicy.savepart   = true;
    netpolicy.overwrite  = true;
    netpolicy.checkstamp = !opt.force;
    strncpy (netpolicy.hostname, host, BUFFSIZE);

    /* if we are downloading checksums list or manifest, file list or packages list was changed.
     * In this case we can skip timestamp check, otherwise file (checksum list or manifest) will
     * seem to be always update !
     */
    if (!strcmp (dfile, CHECKSUMS)
     || !strcmp (dfile, ZMANIFEST))
    {
        netpolicy.checkstamp = false;
    }


	/* make (source and destination) path of our file and a message */
	switch (branch)
    {
    case _PACKAGES:
        snprintf (netpolicy.srcpath, BUFFSIZE, "%s/%s", path, file);
        snprintf (netpolicy.destpath, BUFFSIZE, "%s/%s/%s", cache, name, dfile);
        snprintf (netpolicy.msg, BUFFSIZE, "`- %s %s", act, dfile);
    break;
    case _PATCHES:
        snprintf (netpolicy.srcpath,  BUFFSIZE, "%s/patches/%s", path, file);
        snprintf (netpolicy.destpath, BUFFSIZE, "%s/%s/patches/%s", cache, name, dfile);
        snprintf (netpolicy.msg,      BUFFSIZE, "`- %s patches %s", act, dfile);
    break;
    case _EXTRA:
        snprintf (netpolicy.srcpath,  BUFFSIZE, "%s/extra/%s", path, file);
        snprintf (netpolicy.destpath, BUFFSIZE, "%s/%s/extra/%s", cache, name, dfile);
        snprintf (netpolicy.msg,      BUFFSIZE, "`- %s extra %s", act, dfile);
    break;
    default:
        slassert (NULL);
        break;
	
	}
    if(opt.wget){
            switch (REPOS[index].proto_t) {
                case proto_http: return get_file_over_wget (&netpolicy,true);  break;
                case proto_ftp:  return get_file_over_wget (&netpolicy,false);  break;
                case proto_file: return get_file_over_fs   (&netpolicy);  break;
                default:   slassert (NULL);                               break;
            }
    }else{
            switch (REPOS[index].proto_t) {
		case proto_http: return get_file_over_http (&netpolicy);  break;
		case proto_ftp:  return get_file_over_ftp  (&netpolicy);  break;
		case proto_file: return get_file_over_fs   (&netpolicy);  break;
		default:   slassert (NULL);                               break;
	    }
    }

	return 0;
}

/* uncompress MANIFEST.bz2 of repository `i' branch `b' */
static void
explode_manifest (unsigned i, branches b)
{
    const char *sbranches[BRANCHES] = { "patches", "\b", "extra" };
    
    fprintf (stdout, ">> Uncompressing %s %s: ", sbranches[b], ZMANIFEST);
    fflush (stdout);

	if (!bz_decompress (make_rpath (i, b, ZMANIFEST), NULL))
	 fprintf (stdout, "done.\n");

    return;
}

/* File downloaded or already updated... */
static bool
down_ok (int rval)
{
    return (rval == FILE_DOWNLOADED || rval == FILE_ALREADY_UPDATE);
}

static void
update_mirror_index (unsigned index)
{
    const char *cache = opt.cache;
    FILE *fd;
    char ipath[BUFFSIZE0];

    snprintf (ipath, BUFFSIZE, "%s/slackware/mirror.slackyd", cache);
    
    /* update index of used repository */
    if ((fd = fopen (ipath, "w")))
    {
        fprintf (fd, "[%s][%s]\n", REPOS[index].hostname, REPOS[index].path);
        fclose (fd);
    }
    else
    {
        printfw ("\nWarning: cannot save used mirror.\n"
                 "%s: %s\n\n", ipath, strerror (errno));
    }

    return;
}

/* update repository file list and checksum list */
int
update (void)
{
    const char *cache = opt.cache;
    branches official_branches[BRANCHES] = { _PACKAGES, _PATCHES, _EXTRA };
    const char *official_files[] = { PACKAGES, ZMANIFEST, NULL };
    const unsigned fall = 8;
    unsigned r = 0, fdown = 0, i, j;
    bool slackware = false;
    int rval;
    char ipath[BUFFSIZE0];
        
    if (!opt.force && opt.warn && (rval = packages_list_check (false, PKGLIST_CHECK_QUIT_NEVER)) > 0)
    {
        fprintf (stderr,
         "*** Warning: Broken packages list, %d file%s missing.\n"
         "*** Try to force update or fix your slackyd.conf.\n\n",
         rval, (rval > 1) ? "s are" : " is");
    }

    update_dir ();
    snprintf (ipath, BUFFSIZE, "%s/slackware/mirror.slackyd", cache);
    
    /* Update official slackware files list */
    while (r < N_REPOS && REPOS[r].SLACKWARE && !slackware && fdown != fall)
    {
        fprintf (stdout, "Repository: %s [%s]", REPOS[r].name, REPOS[r].hostname);
        if (REPOS[r].port) {
            fprintf (stdout, "[port: %d]", REPOS[r].port);
        }
        putchar ('\n');
        
        /* First of all update FILELIST.TXT;
         * If it is already update, we assume that all is update and break. Else
         * if it cannot be downloaded we assume that repository is not standard.
         * After download CHECKUMS.md5..."
         */
        rval = update_get_file (r, _PACKAGES, FILELIST);
        if (rval == FILE_ALREADY_UPDATE)
        {
            if (!file_exist (ipath, NULL, true))
             update_mirror_index (r);
            break;
        }

        if (down_ok (rval) &&
            down_ok ((rval = update_get_file (r, _PACKAGES, CHECKSUMS))))
        {
            fdown = 2; /* FILELIST.TXT and CHECKSUMS.md5 was retreived. */
        }
        

       /* For each branch, /, /patches and /extra ... */
        for (i = 0; down_ok (rval) && i < BRANCHES; i++)
        {
            /* For each file, PACKAGES.TXT, CHECKSUMS.TXT and MANIFEST.bz2 ... */
            for (j = 0; down_ok (rval) && official_files[j]; j++)
            {
                rval = update_get_file (r, official_branches[i], official_files[j]);

                /* If we are downloading PACKAGES.TXT and if it is already update,
                 * we assume that CHECKSUMS.TXT and MANIFEST.bz2 *OF SAME BRANCH* is
                 * also updated.
                 */
                if (!strcmp (official_files[j], PACKAGES)
                 && rval == FILE_ALREADY_UPDATE)
                {
                    fdown += 2; /* packages.txt and manifest.bz2 */
                    break;
                }

                /* A MANIFEST.bz2 maybe retreived; uncompress it. */
                if (down_ok (rval) && !strcmp (official_files[j], ZMANIFEST))
                {
                    explode_manifest (r, official_branches[i]);
                }

                /* A file was downloaded or is already update */
                if (down_ok (rval)) fdown++;
            }
        }

        slackware = true;
       
        if (fdown != fall)
        {
            remove (ipath);
            fprintf (stderr, "\nWarning: cannot retreive all file (%u/%u). Trying next: %s\n\n",
                fdown, fall, (r + 1 < N_REPOS && REPOS[r + 1].SLACKWARE) ? "found" : "nothing");
            slackware = false;
        }
        else
        {
            update_mirror_index (r);
        }

        r++;
        
    }

    /* Update extra repository files list */
    while (r < N_REPOS)
    {
        if (REPOS[r].SLACKWARE)
        {
            r++;
            continue;
        }
         
        fprintf (stdout, "Repository: %s [%s]", REPOS[r].name, REPOS[r].hostname);
        if (REPOS[r].port) {
            fprintf (stdout, "[port: %d]", REPOS[r].port);
        }
        putchar ('\n');
        
        if (update_get_file (r, _PACKAGES, FILELIST)  == FILE_DOWNLOADED
         && update_get_file (r, _PACKAGES, PACKAGES)  == FILE_DOWNLOADED
         && update_get_file (r, _PACKAGES, CHECKSUMS) == FILE_DOWNLOADED
         && update_get_file (r, _PACKAGES, ZMANIFEST) == FILE_DOWNLOADED)
        {
            explode_manifest (r, _PACKAGES);
        }

        r++;
    }
        
    return EXIT_SUCCESS;
}

	
/* check for new version available on upgrade, but already installed */
static bool
pkg_u_installed (const char *pkg)
{
    char buffer[BUFFSIZE0] = { 0 }, *p;
    struct stat s;

    snprintf (buffer, BUFFSIZE, "%s/%s", PKGDIR, pkg);
    if (!(p = strrchr (buffer, '.')))
     return false;
    else
     *p = 0x00;
    
    return (!stat (buffer, &s)) ? true : false;
}

static int
search_new (const char *pkgname, upgrade_t *toupgrade[])
{
	unsigned i, j, pnew = 0, sub_new = 0;
    int diff[2], sflags, cflags;
    regex_t preg;
    pkg_t **packages = NULL;
    unsigned npackages = 0x00;
    dlist *official = NULL;
        
    fprintf (stdout, "Reading packages data: ");
    fflush (stdout);

    /* If we won't upgrade official packages replacing it with extra packages
     * load here the slackware list.
     * Otherwise set it to NULL.
     */
    if (!opt.upgrade_replacing_official)
    {
        official = pkglist_official ();
    }

    sflags = (pkgname && opt.use_regex) ? MATCH_USING_REGEX : MATCH_EXACTLY_NAME_INST;

    packages = pkgl2pkgt (search (sflags, pkgname), &npackages);  

    if (!npackages)
    {
        if (!pkgname)
        {
            printf ("\n\nNo packages found !?\nTry to update packages list.\n");
        }
        else
        {
            printf ("nothing to do for `%s'.\n", pkgname);
        }
        dlist_free (&official);
        return -1;
    }
 
    fprintf (stdout, "done.\n");
        
    cflags = REG_EXTENDED | REG_NOSUB;
    if (opt.use_regex && pkgname)
    {
        if (opt.case_insensitive)
         cflags |= REG_ICASE;
        xregcomp (&preg, pkgname, cflags);
    }

    for (i = 0; i < nginst; i++)
    {

    if ((pkgname && opt.use_regex  && regexec (&preg, ginst[i].name, 0, NULL, 0))
     || (pkgname && !opt.use_regex && !xstrstr (ginst[i].name, pkgname)))
    {
        continue;
    }
     
    printfv ("Verifying %s: ", ginst[i].name);
    
    sub_new = 0;
    
    for (j = 0; j < npackages; j++)
    {

        /* If one of this case return to begin for() doing nothing:
         *
         * - current available package name not matched on current package installed
         * - current available packages already installed
         * - current available packages ins't official, current installed is unofficial
         *   and opt.upgrade_replacing_official is false.
         */
        if (strcmp (packages[j]->pstruct.name, ginst[i].pstruct.name)
         || pkg_u_installed (packages[j]->name)
         || (!opt.upgrade_replacing_official && !REPOS[packages[j]->N_REPO].SLACKWARE && dlist_check (official, ginst[i].name)))
        {
            continue;
        }

        diff[0] = strverscmp (ginst[i].pstruct.version, packages[j]->pstruct.version);
	    diff[1] = atoi (ginst[i].pstruct.build) - atoi (packages[j]->pstruct.build);
               
        if (diff[0] < 0
        || (!diff[0] && diff[1] < 0)
        || (!diff[0] && !diff[1] && packages[j]->branch == _PATCHES))
        {
            /* found new available package with version and/or build major to local package */
            
            *toupgrade = xrealloc (*toupgrade, (pnew + 1) * sizeof (upgrade_t));
            /* skip memory leak :P */
            if (sub_new == 0)
            {
                (*toupgrade)[pnew].remote = NULL;
                (*toupgrade)[pnew].local  = xstrdup (ginst[i].name);
            }
            pkg_t_add (&(*toupgrade)[pnew].remote, &sub_new, packages[j]);
        }
    } /* end available packages for() */
    
    if (sub_new > 0)
    {
       	(*toupgrade)[pnew].sub_new = sub_new;
       	pnew++;
       	printfv ("found %u new.\n", sub_new);
    }
    else
    {
        printfv ("nothing to do.\n");
    }
    
	} /* end installed packages list for() */

    
    dlist_free (&official);

    if (opt.use_regex && pkgname)
     regfree (&preg);
    pkg_t_free_all (&packages, npackages);
    
    putchar ('\n');

    if (pnew == 0)
    {
        if (pkgname)
        {
            fprintf (stdout, "All packages \"%s\" are updated.\n", pkgname);
        }
        else
        {
            fprintf (stdout, "All packages are updated.\n");
        }
    }

	return (pnew > 0) ? (int) pnew : -1;
}


/* upgrade packages installed */
int
upgrade (const char *pkgname)
{
    pkg_t **gpkg = NULL, **rptr;
    int i, pnew, iflags;
    unsigned j, ngpkg = 0;
    upgrade_t *toupgrade = NULL;
    char c = 0;
    
    choose_dep_t ddata;
	pkg_t **prequired = NULL;
    unsigned nprequired = 0;
    bool ch;

    memset (&ddata, 0, sizeof (ddata));

	packages_list_check (true, PKGLIST_CHECK_QUIT_ON_ALL);

    iflags = (pkgname && opt.use_regex) ? MATCH_USING_REGEX : MATCH_ALL_NAME;
    if (pkgname && is_installed (pkgname, iflags, 0) == PACKAGE_STATUS_NOT_INSTALLED)
    {
        fprintf (stderr, "No packages \"%s\" are installed.\n", pkgname);
        return EXIT_FAILURE;
    }
    

    if ((pnew = search_new (pkgname, &toupgrade)) < 1)
    {
        return EXIT_FAILURE;
    }

    fprintf (stdout,
    "Found %d package%s to upgrade:\n"
    "----------------------------- \n", pnew, (pnew > 1) ? "s" : "");

    for (i = 0; i < pnew; i++)
    {
        rptr = toupgrade[i].remote;
        fprintf (stdout, "%s:\n", toupgrade[i].local);
        for (j = 0; j < toupgrade[i].sub_new - 1; j++)
        {
            fprintf (stdout, "\t%s %s\n", rptr[j]->name, pkg_type (rptr[j]));
        }
        fprintf (stdout, "\t%s %s\n", rptr[j]->name, pkg_type (rptr[j]));    
	}

    putchar ('\n');

    /* choice package to upgrade */
    for (i = 0; i < pnew; i++)
    {

    rptr = toupgrade[i].remote;
    /* set `ch' to false; we use this variable to track package choice */
    ch = false;

    if (toupgrade[i].sub_new > 1)
    {
        sort_pkg (&rptr, &toupgrade[i].sub_new);

		fprintf (stdout, "Found %u different new version of package %s:\n",
            toupgrade[i].sub_new,
            rptr[0]->pstruct.name);

		for (j = 0; j < toupgrade[i].sub_new; j++)
        {
            fprintf (stdout, "  --> %s %s\n", rptr[j]->name, pkg_type (rptr[j]));
        }
    }

    for (j = 0; j < toupgrade[i].sub_new; j++)
    {

        /* Check for package already in dependencies list */
        if (pkg_t_check (rptr[j]->pstruct.name, prequired, nprequired, MATCH_EXACTLY_NAME))
        {
            break;
        }

        if (!opt.force)
        {
            if (j == 0) {
                fprintf (stdout, "Upgrade %s to:\n", toupgrade[i].local);
            }
            fprintf (stdout, "\t%s %s ? [y/N] ",
                rptr[j]->name, (toupgrade[i].sub_new == 1) ? pkg_type (rptr[j]) : "\b");
        }
        else
        if (toupgrade[i].sub_new > 1) {
            fprintf (stdout, "Will be used %s !\n", rptr[0]->name);
        }

        fflush (stdout);

        if (opt.force || (c = getchar()) == 'Y' || c == 'y')
        {

            ch = true;
            ngpkg++;

            gpkg = (pkg_t **)
                xrealloc (gpkg, ngpkg * sizeof (pkg_t *));
            gpkg[ngpkg - 1] = pkg_t_dup (rptr[j]);

            if (!opt.force)
            {
                clrbuff();
            }
            
            break;
        }
        
        if (c != '\n') {
            clrbuff();
        }
    }

    free (toupgrade[i].local);
    pkg_t_free_all (&toupgrade[i].remote, toupgrade[i].sub_new);

    if (ch && opt.check_dep)
    {
        /* search missing packages dependencies in repository. */
        if (opt.check_dep && opt.resolve_dep)
        {
			ddata.next  = gpkg;
			ddata.nnext = ngpkg;
            choice_dep (&ddata, gpkg[ngpkg - 1], DEP_T_REQUIRED);
			choice_dep (&ddata, gpkg[ngpkg - 1], DEP_T_SUGGESTED);
		}
	}
	}

	free (toupgrade);

    if (!opt.force)
     putchar ('\n');
    
    /* download choosed packages suggested and required */
    if ((prequired = pkgl2pkgt (ddata.added, &nprequired)))
	{
		for (j = 0; j < nprequired; j++)
    	{
        	if (get_pkg (prequired[j]) == EXIT_SUCCESS)
        	{
            	verify_md5 (prequired[j]);
        	}
		}
		pkg_t_free_all (&prequired, nprequired);
    }
  
    
    if (ngpkg == 0)
     fprintf (stdout, "Nothing was choosed.\n");
    else
    {
        for (j = 0; j < ngpkg; j++)
        {
            if (get_pkg (gpkg[j]) == EXIT_SUCCESS)
            {
                verify_md5 (gpkg[j]);
            }
        }
    }
    
    pkg_t_free_all (&gpkg, ngpkg);
    
    return EXIT_SUCCESS;

}
