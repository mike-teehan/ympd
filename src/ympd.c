/* ympd
   (c) 2013-2014 Andrew Karpow <andy@ndyk.de>
   This project's homepage is: http://www.ympd.org

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <pthread.h>

#include "mongoose.h"
#include "http_server.h"
#include "mpd_client.h"
#include "config.h"

extern char *optarg;

int force_exit = 0;

void bye()
{
    force_exit = 1;
}

int modify_passwords_file(const char *fname, const char *domain,
                             const char *user, const char *pass) {
	int found;
	char line[512], u[512], d[512], ha1[33], tmp[512];
	FILE *fp, *fp2;

	found = 0;
	fp = fp2 = NULL;

	// Regard empty password as no password - remove user record.
	if (pass != NULL && pass[0] == '\0') {
		pass = NULL;
	}

	(void) snprintf(tmp, sizeof(tmp), "%s.tmp", fname);

	// Create the file if does not exist
	if ((fp = fopen(fname, "a+")) != NULL) {
		(void) fclose(fp);
	}

	// Open the given file and temporary file
	if ((fp = fopen(fname, "r")) == NULL) {
		return 0;
	} else if ((fp2 = fopen(tmp, "w+")) == NULL) {
		fclose(fp);
		return 0;
	}

	// Copy the stuff to temporary file
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "%[^:]:%[^:]:%*s", u, d) != 2) {
			continue;
		}

		if (!strcmp(u, user) && !strcmp(d, domain)) {
		found++;
		if (pass != NULL) {
			mg_md5(ha1, user, ":", domain, ":", pass, NULL);
			fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
		}
		} else {
			(void) fprintf(fp2, "%s", line);
		}
	}

	// If new user, just add it
	if (!found && pass != NULL) {
		mg_md5(ha1, user, ":", domain, ":", pass, NULL);
		(void) fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
	}

	// Close files
	(void) fclose(fp);
	(void) fclose(fp2);

	// Put the temp file in place of real file
	(void) remove(fname);
	(void) rename(tmp, fname);

	return 1;
}

static int do_auth(struct mg_connection *conn) {
	int result = MG_FALSE; // Not authorized
	FILE *fp;

	// To populate passwords file, do
	// mongoose -A my_passwords.txt mydomain.com admin admin
	if ((fp = fopen(".htpasswd", "r")) != NULL) {
		result = mg_authorize_digest(conn, fp);
		fclose(fp);
	}

	return result;
}

static int server_callback(struct mg_connection *conn, enum mg_event ev) {
    switch(ev) {
        case MG_CLOSE:
            mpd_close_handler(conn);
            return MG_TRUE;
        case MG_REQUEST:
            if (conn->is_websocket) {
                conn->content[conn->content_len] = '\0';
                if(conn->content_len)
                    return callback_mpd(conn);
                else
                    return MG_TRUE;
            } else
#ifdef WITH_DYNAMIC_ASSETS
                return MG_FALSE;
#else
                return callback_http(conn);
#endif
        case MG_AUTH:
			return do_auth(conn);
        default:
            return MG_FALSE;
    }
}

static void printUsage(const char* exename) {
	fprintf(stderr, "Daemon Mode:\n"
			" Usage: %s [OPTION]...\n\n"
			" -h, --host <host>\t\tconnect to mpd at host [localhost]\n"
			" -p, --port <port>\t\tconnect to mpd at port [6600]\n"
			" -w, --webport [ip:]<port>\tlisten interface/port for webserver [8080]\n"
			" -u, --user <username>\t\tdrop priviliges to user after socket bind\n"
			" -V, --version\t\t\tget version\n"
			" --help\t\t\t\tthis help\n"
			"\n"
			"Password Mode:\n"
			" Usage %s -A <htpasswd_file> <realm> <user> <passwd>\n\n"
			, exename, exename);
}

int main(int argc, char **argv)
{
    int n, option_index = 0;
    struct mg_server *server = mg_create_server(NULL, server_callback);

    mg_set_option(server, "ports", "8080");

    unsigned int current_timer = 0, last_timer = 0;
    char *run_as_user = NULL;
    char const *error_msg = NULL;
    char *webport = "8080";

    atexit(bye);
#ifdef WITH_DYNAMIC_ASSETS
    mg_set_option(server, "document_root", SRC_PATH);
#endif

    mpd.port = 6600;
    strcpy(mpd.host, "127.0.0.1");

    static struct option long_options[] = {
		{"htpasswd",     required_argument, 0, 'A'},
        {"host",         required_argument, 0, 'h'},
        {"port",         required_argument, 0, 'p'},
        {"webport",      required_argument, 0, 'w'},
        {"user",         required_argument, 0, 'u'},
        {"version",      no_argument,       0, 'v'},
        {"help",         no_argument,       0,  0 },
        {0,              0,                 0,  0 }
    };

    while((n = getopt_long(argc, argv, "A:h:p:w:u:v",
                long_options, &option_index)) != -1) {
		if(option_index == 0 && n == 'A') {
			int ret = EXIT_FAILURE;
			while(1) {
				if(argc != 6) {
					printUsage(argv[0]);
					break;
				}
				if(modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ) {
					fprintf(stderr, "%s updated.\n", argv[2]);
					ret = EXIT_SUCCESS;
				} else {
					fprintf(stderr, "%s updated.\n", argv[2]);
				}
				break;
			}
			return ret;
		}
		switch (n) {
            case 'h':
                strncpy(mpd.host, optarg, sizeof(mpd.host));
                break;
            case 'p':
                mpd.port = atoi(optarg);
                break;
            case 'w':
                webport = strdup(optarg);
                break;
            case 'u':
                run_as_user = strdup(optarg);
                break;
            case 'v':
                fprintf(stdout, "ympd  %d.%d.%d\n"
                        "Copyright (C) 2014 Andrew Karpow <andy@ndyk.de>\n"
                        "built " __DATE__ " "__TIME__ " ("__VERSION__")\n",
                        YMPD_VERSION_MAJOR, YMPD_VERSION_MINOR, YMPD_VERSION_PATCH);
                return EXIT_SUCCESS;
                break;
            default:
				printUsage(argv[0]);
				return EXIT_FAILURE;
        }

        if(error_msg)
        {
            fprintf(stderr, "Mongoose error: %s\n", error_msg);
            return EXIT_FAILURE;
        }
    }

    error_msg = mg_set_option(server, "listening_port", webport);
    if(error_msg) {
        fprintf(stderr, "Mongoose error: %s\n", error_msg);
        return EXIT_FAILURE;
    }

    /* drop privilges at last to ensure proper port binding */
    if(run_as_user != NULL) {
        error_msg = mg_set_option(server, "run_as_user", run_as_user);
        free(run_as_user);
        if(error_msg)
        {
            fprintf(stderr, "Mongoose error: %s\n", error_msg);
            return EXIT_FAILURE;
        }
    }

    while (!force_exit) {
        mg_poll_server(server, 200);

        current_timer = time(NULL);
        if(current_timer - last_timer)
        {
            last_timer = current_timer;
            mpd_poll(server);
        }
    }

    mpd_disconnect();
    mg_destroy_server(&server);

    return EXIT_SUCCESS;
}
