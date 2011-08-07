/*
 *      getmd5(), md5file();
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
#include "openssl/md5.h"
#define MD5LEN      0x10 /* 16, md5 length */
#define STRMD5LEN   (MD5LEN * 0x02)

/* Check for md5 hash on first 32 bytes of `hash' */
static bool
ismd5 (const char *hash)
{
    unsigned short i = 0, m = MD5LEN * 2;

    if (strlen (hash) < m)
    {
        return false;
    }
    else
    {
        while (i < m)
        {
            if (!isxdigit (hash[i++]))
            {
                return false;
            }
        }
    }
    return true;
}

/* search hash of `file' in `checksum_path' file path and return md5 string.
 * If nothing found or an error occured, return NULL.
 */
char *
getmd5 (const char *file, const char *checksum_path)
{
    const char endlim[] = " \n\t";
    char buffer[BUFFSIZE0];
    FILE *fd;
    int len;

    slassert (file != NULL);
    
    errno = 0x00;

    if (!(fd = fopen (checksum_path, "r")))
    {
     	return NULL;
	}

    while (fgets (buffer, BUFFSIZE, fd))
    {
        if (strstr (buffer, file) == NULL)
        {
            continue;
        }

        len = strlen (buffer) - 1;
        while (len > 1 && strchr (endlim, buffer[len]))
        {
            buffer[len--] = 0x00;
        }
        len++;

        len -= strlen (file);

        if (len > 0 && buffer[len - 1] == '/' && !strcmp (buffer + len, file))
        {
            if (ismd5 (buffer))
            {
                fclose (fd);
                return xstrndup (buffer, STRMD5LEN); /* return hash */
            }
        }
    }

    fclose (fd);
    return NULL; /* hash not found */
}


/* Verify if MD5 hash of file `filename' is equal to hash `checksum'. */
void md5file(char *filename, char *checksum, const char *md5list)
{
    FILE *fd;
    MD5_CTX ctx;
    int i, p = 0x00;
    unsigned len;
    unsigned char buffer[BUFFSIZE0], digest[MD5LEN] = { 0 };
    char hash[STRMD5LEN + 1] = { 0 };

    fprintf (stdout, "\r* Verify md5 checksum: ");
    fflush (stdout);

    if (checksum == NULL) {
        if (errno == 0x00)
         fprintf (stdout, "not found !\n");
        else
         fprintf (stdout, "%s: %s.\n", md5list, strerror (errno));
        return;
    }

    slassert (filename);
    
    if ((fd = fopen (filename, "rb")) == NULL)
    {
		fprintf (stdout, "error, %s: %s\n", filename, strerror (errno));
		return;
    }

    MD5_Init(&ctx);
    while ((len = fread (buffer, 1, BUFFSIZE, fd)))
    {
		MD5_Update (&ctx, buffer, len);
    }

    MD5_Final (digest, &ctx);
    fclose (fd);

    for (i = 0; i < MD5LEN; i++, p += 2)
    {
		sprintf((char *) hash + p, "%02x", digest[i]);
    }

    if (strcmp (hash, checksum))
    {
		fprintf (stdout, "\n\n"
		">>> WARNING : %s hash mismatch.\n"
		">>> Original: %s\n"
		">>> Checked : %s\n\n", filename, checksum, hash);
	}
    else
    {
        fprintf (stdout, "ok.\n");
    }
    return;
}


