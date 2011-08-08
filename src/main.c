/*
 *      main.c
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
usage(char *prgname)
{
    fprintf (stderr, "Usage: %s <options> <package>             \n\n", prgname);
    fprintf (stderr, "Options:                                             \n");
    fprintf (stderr, " -5: Skip md5 verify.                                \n");
    fprintf (stderr, " -b: Try to download package build sources.          \n");
    fprintf (stderr, " -B: Try to build package from sources.              \n");
    fprintf (stderr, " -c: Use alternate config file.                      \n");
    fprintf (stderr, " -d: Search missing shared libraries of installed packages.\n");
    fprintf (stderr, " -D: Search missing required packages (packager-indicated).\n");
    fprintf (stderr, " -e: Use regex.                                      \n");
    fprintf (stderr, " -f: Force update or packages download. Assume yes to all question.\n");
    fprintf (stderr, " -g: Download package.                               \n");
    fprintf (stderr, " -h: Show this help.                                 \n");
    fprintf (stderr, " -I: Skip packages status check.                     \n");
    fprintf (stderr, " -l: List all packages installed.                    \n");
    fprintf (stderr, " -L: List all non-slackware packages installed.      \n");
    fprintf (stderr, " -m: Case insensitive.                               \n");
    fprintf (stderr, " -n: Only notify broken dependencies.                \n");
    fprintf (stderr, " -O: List all orphan packages.                       \n");
    fprintf (stderr, " -p: Clean slackyd directory (only packages and sources).\n");
    fprintf (stderr, " -P: Clean slackyd directory (all).                  \n");
    fprintf (stderr, " -q: Quiet, disable some warnings.                   \n");
    fprintf (stderr, " -r: Search not official replaceable packages.       \n");
    fprintf (stderr, " -R: Show repositories statistics.                   \n");
    fprintf (stderr, " -s: Search package.                                 \n");
    fprintf (stderr, " -S: Skip dependencies check.                        \n");
    fprintf (stderr, " -t: Specify a path to download packages             \n");
    fprintf (stderr, " -u: Update packages list and md5 hash list.         \n");
    fprintf (stderr, " -U: Search new packages.                            \n");
    fprintf (stderr, " -v: Verbose mode.                                   \n");
    fprintf (stderr, " -V: Show slackyd info.                              \n");
    fprintf (stderr, " -w: View package info.                              \n");
    fprintf (stderr, " -x: Disable blacklist.                              \n");
    fprintf (stderr, " -X: Show packages available and blacklisted.        \n");
    
    
    exit(EXIT_FAILURE);
}


int
main(int argc, char **argv)
{
    unsigned packages_found = 0;
    pkg_t **packages = NULL;
    int i, sflag;

#if defined MTRACE
    mtrace();
#endif

    if (parse_options(argc, argv))
	 usage(*argv);

    parse_config ();

	putchar ('\n');
	
    xstrstr = (opt.case_insensitive) ? strcasestr : strstr;
	xstrcmp = (opt.case_insensitive) ? strcasecmp : strcmp;

    /* Load packages installed and split all folds.
	 * Save in a global installed_t struct because
	 * too many function they need.
	 */
	 nginst = installed (&ginst);

    /* update */
    if (opt.update)
	 update();

    /* upgrade all packages */
    if (opt.upgrade)
     upgrade (opt.package);

    /* search */
    if (opt.search || opt.get || opt.view || opt.getsrc || opt.buildsrc)
    {

    packages_list_check (true, PKGLIST_CHECK_QUIT_ON_ALL);
    	
	fprintf (stdout, "Searching %s: ", (opt.package) ? opt.package : "all");
	fflush (stdout);
	
	sflag = (!opt.package || !opt.use_regex) ? MATCH_ALL_NAME : MATCH_USING_REGEX;

	packages = pkgl2pkgt (search (sflag, opt.package), &packages_found);

	if (packages_found == 0)
	 fprintf (stdout, "nothing found.");
    else
     fprintf (stdout, "found %u package%s.\n", packages_found, (packages_found > 1) ? "s" : "");
        
    if (packages_found > 1000)
     fprintf (stdout, "Sorting packages: ");
	fflush (stdout);
	sort_pkg (&packages, &packages_found);
	if (packages_found > 1000)
     fprintf (stdout, "done.\n");
	putchar ('\n');
	show_pkg_found (packages, packages_found);

	}

    /* get */
    if (opt.get)
	 get (&packages, &packages_found);
   
    /* get build sources */
    if (opt.getsrc || opt.buildsrc)
	 pkgsrc_get (&packages, &packages_found);
    
    /* check for missing shared libraries */
    if (opt.shared_dep)
     check_shared_dep (opt.package);

    /* check for missing packager-indicated library */
    if (opt.packager_dep)
     search_packager_lib (opt.package);

    /* view */
    if (opt.view)
	 show_package_info (packages, packages_found);


    /* show packages installed */
    if (opt.installed)
	 installed_packages (opt.package);

    /* show non-slackware packages installed */
    if (opt.nslack_installed)
	 unofficial_packages (opt.package);

    /* show obsolete packages, installed but missing from repositories */
    if (opt.obsolete)
     obsolete_packages (opt.package);
     
    /* show blacklisted packages available */
    if (opt.show_blacklisted)
	 blacklisted_packages (opt.package);

    if (opt.replaceable)
     replaceable_packages (opt.package);

    /* show repositoies stat */
    if (opt.rstat)
     rstat();

    /* clean slackyd directory */
    if (opt.purge_all)
    {
        fprintf (stdout, "Cleaning cache...\n");
        purge (PURGE_ALL);
    }
    if (opt.purge)
    {
        fprintf (stdout, "Removing packages and sources...\n");
        purge (PURGE_PKG);
    }
    
    putchar ('\n');
    
    /* cleanup */
	free_installed_t (&ginst, nginst);
    pkg_t_free_all (&packages, packages_found);

    for (i = (signed)N_REPOS - 1; i >= 0; i--)
	{
		free (REPOS[i].name);
		free (REPOS[i].hostname);
		free (REPOS[i].path);
	}
	free (REPOS);

	free (opt.package);
	free (opt.config);
    free (opt.cache);
    
	while ((opt.nblacklisted--) > 0)
	{
	    regfree (&opt.blacklisted[opt.nblacklisted]);
	}
    free (opt.blacklisted);

	return EXIT_SUCCESS;
}
