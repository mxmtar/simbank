
#include "autoconfig.h"

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "simbank/simcard-def.h"

#include "iso_iec_7816.h"
#include "3gpp_ts_11_11.h"
#include "3gpp_ts_101_221.h"

#include "ss9006.h"

#include "x_timer.h"

#define mmax(_lhs, _rhs) ((_lhs > _rhs) ? _lhs : _rhs)
#define mmin(_lhs, _rhs) ((_lhs < _rhs) ? _lhs : _rhs)

int string_is_digit(const char *str)
{
	int len;
	char *test;

	if (!(test = (char *)str)) {
		return 0;
	}
	if (!(len = strlen(test))) {
		return 0;
	}
	while (len--) {
		if (!isdigit(*test++)) {
			return 0;
		}
	}
	return -1;
}

int is_int_value_in_set(int value, const char *set)
{
	int res;
	int min, max;
	char *chunk, *next, *input, *minp, *maxp;

	res = 0; // out of set
	input = strdup(set);

	if (!input) {
		res = -1; // in set
		goto is_int_value_in_set_end;
	}
	next = input;
	while (next) {
		chunk = strsep(&next, ",");
		if (chunk) {
			if (!strcasecmp("all", chunk)) {
				res = -1; // in set
				goto is_int_value_in_set_end;
			}
			min = max = -1;
			maxp = chunk;
			minp = strsep(&maxp, "-");
			if (string_is_digit(minp)) {
				min = max = atoi(minp);
			}
			if (string_is_digit(maxp)) {
				max = atoi(maxp);
			}
			if ((max >= min) && (value >= min) && (value <= max)) {
				res = -1; // in set
				goto is_int_value_in_set_end;
			}
		}
	}

is_int_value_in_set_end:
	if (input) {
		free(input);
	}
	return res;
}

void dumphex(FILE *fp, const void *data, size_t length)
{
	size_t i;
	const unsigned char *tp = data;

	for (i = 0; i < length; i++) {
		if ((i%16) == 0) {
			if (i) {
				fprintf(fp, "\n");
			}
			fprintf(fp, "%0*x: ", 4, (unsigned int)i);
		} else if ((i) && ((i%8) == 0)) {
			fprintf(fp, "  ");
		} else if (i) {
			fprintf(fp, " ");
		}
		fprintf(fp, "%02x", tp[i]);
	}
	fprintf(fp, "\n");
}

void dumptime(FILE *fp)
{
	struct timeval tv;
	struct tm *tmptr;

	gettimeofday(&tv, NULL);
	tmptr = localtime(&tv.tv_sec);
	fprintf(fp, "%4d/%02d/%02d %02d:%02d:%02d.%06u: ",
		tmptr->tm_year + 1900,
		tmptr->tm_mon + 1,
		tmptr->tm_mday,
		tmptr->tm_hour,
		tmptr->tm_min,
		tmptr->tm_sec,
		(unsigned int)(tv.tv_usec));
}

#define SIMBANK_SIMCARD_MAX 200
#define SIMBANK_SIMCARD_FREQUENCY 4608000

enum {
	SIMBANK_SIMCARD_STATE_DISABLE = 0,
	SIMBANK_SIMCARD_STATE_RESET,
	SIMBANK_SIMCARD_STATE_IDLE,
	SIMBANK_SIMCARD_STATE_PPS,
	SIMBANK_SIMCARD_STATE_RUN,
};

struct simcard {
	char prefix[32];
	int fd;
	struct {
		struct x_timer enable;
		struct x_timer reset;
		struct x_timer atr;
		struct x_timer wait_time;
		struct x_timer command;
		struct x_timer status;
	} timers;
	struct {
		u_int32_t busy:1;
		u_int32_t inserted:1;
		u_int32_t reset:1;
		u_int32_t reseting:1;
		u_int32_t iccid:1;
		u_int32_t iccid_req:1;
		u_int32_t imsi:1;
		u_int32_t imsi_req:1;
		u_int32_t spn:1;
		u_int32_t spn_req:1;
		u_int32_t msisdn:1;
		u_int32_t msisdn_req:1;
		u_int32_t erase_sms:1;
		u_int32_t erase_sms_req:1;
	} flags;
	int state;
	int client;
	struct iso_iec_7816_device ifacedev;
	// debug
	char *dump;
	char *log;
};

struct simcard simcards[SIMBANK_SIMCARD_MAX];

char tcp_ss9006_prefix[64];
int tcp_ss9006_sock;
struct sockaddr_in tcp_ss9006_loc_addr;
socklen_t tcp_ss9006_loc_addrlen;
struct sockaddr_in tcp_ss9006_rem_addr;
socklen_t tcp_ss9006_rem_addrlen;

struct tcp_ss9006_client {
	char prefix[64];
	int sock;
	struct sockaddr_in addr;
	socklen_t addrlen;
	u_int8_t recv_buf[0x10000];
	size_t recv_length;
	size_t recv_wait;
	u_int8_t xmit_buf[0x10000];
	size_t xmit_length;
	size_t xmit_length_position;
	struct tcp_ss9006_client_timers {
		struct x_timer auth;
		struct x_timer watchdog;
	} timers;
	struct tcp_ss9006_client_flags {
		unsigned int control:1;
		unsigned int close:1;
	} flags;
	// debug
	char *dump;
	char *log;
};

#define TCP_SS9006_CLIENT_MAX_COUNT 32

struct tcp_ss9006_client *tcp_ss9006_clients = NULL;

int default_port = 9006;
char *default_user = "login";
char *default_password = "password";

size_t default_ss9006_client_count = 4;

int run = 1;
int daemonize = 1;

int sim_monitor = -1;

char *log_dir = "/var/log/simbank";
char *log_file = NULL;
char *pid_file = "/var/run/simbank.pid";

char *prefix = "SB";
static char options[] = "ac:d:efhl:m:p:s:t:u:vw:x";
static char usage[] = "Usage: simbank [options]\n"
"Options:\n"
"\t-a - exit on error\n"
"\t-c <count> - client count (default:4)\n"
"\t-d <unit> [<set>] - dump data \"sim\",\"client\"\n"
"\t-e - erase dump & log file(s)\n"
"\t-f - foreground mode\n"
"\t-h - print this message\n"
"\t-l <unit> [<set>] - log \"general\",\"sim\",\"client\"\n"
"\t-m <sim> - enable SIM monitor\n"
"\t-p <port> - server port (default:9006)\n"
"\t-s <password> - user password (default:password)\n"
"\t-t <time> - watchdog wait time (default:60, disable:0)\n"
"\t-u <login> - user login (default:login)\n"
"\t-v - print version\n"
"\t-w - SIM response wait time 0-30 seconds (default:0)\n"
"\t-x - erase all SMS\n";

#define LOG(_fmt, _args...) \
do { \
	FILE *__fp; \
	if ((log_file) && (__fp = fopen(log_file, "a"))) { \
		dumptime(__fp); \
		fprintf(__fp, _fmt, ##_args); \
		fflush(__fp); \
		fclose(__fp); \
	} \
	if (!daemonize) { \
		dumptime(stdout); \
		fprintf(stdout, _fmt, ##_args); \
		fflush(stdout); \
	} \
} while(0)

void tcp_ss9006_cli_msg_ext_init(struct tcp_ss9006_client *cli, u_int8_t msgid, u_int8_t d0, u_int8_t d1, u_int8_t d2)
{
	cli->xmit_buf[cli->xmit_length++] = SS9006_OPC_EXTENSION;
	cli->xmit_buf[cli->xmit_length++] = msgid;
	cli->xmit_buf[cli->xmit_length++] = d0;
	cli->xmit_buf[cli->xmit_length++] = d1;
	cli->xmit_buf[cli->xmit_length++] = d2;
	cli->xmit_length_position = cli->xmit_length++;
	cli->xmit_buf[cli->xmit_length_position] = 0;
}

void tcp_ss9006_cli_msg_ext_add_param(struct tcp_ss9006_client *cli, u_int8_t prmid, u_int8_t length, void *data)
{
	cli->xmit_buf[cli->xmit_length_position] += 2 + length;
	cli->xmit_buf[cli->xmit_length++] = prmid;
	cli->xmit_buf[cli->xmit_length++] = length;
	memcpy(&cli->xmit_buf[cli->xmit_length], data, length);
	cli->xmit_length += length;
}

void tcp_ss9006_cli_msg_ext_add_param_string(struct tcp_ss9006_client *cli, u_int8_t prmid, const char *fmt, ...)
{
	int length;
	va_list ap;

	va_start(ap, fmt);
	length = vsprintf((char *)&cli->xmit_buf[cli->xmit_length + 2], fmt, ap);
	va_end(ap);

	cli->xmit_buf[cli->xmit_length_position] += 2 + length;
	cli->xmit_buf[cli->xmit_length++] = prmid;
	cli->xmit_buf[cli->xmit_length++] = length;
	cli->xmit_length += length;
}

enum {
	SIM_RESTART_FLAG_CLI = (1 << 0),
	SIM_RESTART_FLAG_SMS = (1 << 1),
};

void simcard_restart(struct simcard *simcard, u_int32_t timeout, u_int32_t flags)
{
	// set SIM-card state to disable
	simcard->state = SIMBANK_SIMCARD_STATE_DISABLE;
	// start enable timer
	x_timer_set_ms(simcard->timers.enable, timeout);
	// stop rest timers
	x_timer_stop(simcard->timers.reset);
	x_timer_stop(simcard->timers.atr);
	x_timer_stop(simcard->timers.wait_time);
	x_timer_stop(simcard->timers.command);
	x_timer_stop(simcard->timers.status);
	// init flags
	simcard->flags.reset = 0;
	if (flags & SIM_RESTART_FLAG_CLI) {
		simcard->flags.reseting = 0;
		simcard->flags.busy = 0;
		simcard->flags.iccid = 0;
		simcard->flags.iccid_req = 1;
		simcard->flags.imsi = 0;
		simcard->flags.imsi_req = 1;
		simcard->flags.spn = 0;
		simcard->flags.spn_req = 1;
		simcard->flags.msisdn = 0;
		simcard->flags.msisdn_req = 1;
		simcard->flags.erase_sms = 0;
		if (flags & SIM_RESTART_FLAG_SMS) {
			simcard->flags.erase_sms_req = 1;
		}
		// init text fields
		simcard->ifacedev.iccid_len = 0;
		simcard->ifacedev.imsi_len = 0;
		simcard->ifacedev.spn_len = 0;
		simcard->ifacedev.msisdn_len = 0;
		// reset client binding
		simcard->client = -1;
	}
}

void main_exit(int signal)
{
	LOG("%s: catch signal \"%d\"\n", prefix, signal);
	switch (signal) {
		case SIGSEGV:
			exit(EXIT_FAILURE);
			break;
		default:
			run = 0;
			break;
	}
}

int main(int argc, char **argv)
{
	int abort = 0;
	int erase_dump = 0;
	u_int32_t wait_time = 0;

	int port = 0;
	char *user = NULL;
	char *password = NULL;
	size_t ss9006_client_count = 0;

	u_int32_t watchdog_time = 60;

	u_int8_t sim_start = 0xff;
	u_int8_t sim_end = 0xff;

	u_int32_t sim_restart_flags = 0;

	int opt;

	char *dump_sim = NULL;
	char *dump_client = NULL;

	char *log_sim = NULL;
	char *log_client = NULL;
	char *log_general = NULL;

	char path[PATH_MAX];

	struct timeval timeout;
	fd_set rfds;
	int maxfd;

	struct simcard_data sc_read_data, sc_write_data;

	pid_t pid;
	FILE *fp;
	int res;
	size_t i, j, k;

	ssize_t rlen;

	u_int16_t tmpu16;
	int tmp_flags;
	int tmp_opt;
#if 1
	u_int8_t select_header[5];
	u_int8_t select_data[2];
#else
	u_int8_t status_header[5];
#endif
	struct ss9006_base_header *tcp_ss9006_base_header;
	struct ss9006_authorization_request *tcp_ss9006_authorization_request;
	struct ss9006_authorization_response *tcp_ss9006_authorization_response;
	struct ss9006_sim_generic_request *tcp_ss9006_sim_generic_request;
	struct ss9006_sim_reset_response *tcp_ss9006_sim_reset_response;
	struct ss9006_combined_header *tcp_ss9006_combined_header;
	struct ss9006_combined_chunk_header *tcp_ss9006_combined_chunk_header;
	struct ss9006_sim_status_response *tcp_ss9006_sim_status_response;
	struct ss9006_sim_extension_request *tcp_ss9006_sim_extension_request;

	// get options
	while ((opt = getopt(argc, argv, options)) != -1) {
		switch (opt) {
			case 'a':
				abort = 1;
				break;
			case 'c':
				ss9006_client_count = atoi(optarg);
				break;
			case 'd':
				if (!strcmp(optarg, "sim")) {
					dump_sim = argv[optind];
					if ((!dump_sim) || (*dump_sim == '-')) {
						dump_sim = "all";
					}
				} else if (!strcmp(optarg, "client")) {
					dump_client = argv[optind];
					if ((!dump_client) || (*dump_client == '-')) {
						dump_client = "all";
					}
				}
				break;
			case 'e':
				erase_dump = 1;
				break;
			case 'f':
				daemonize = 0;
				log_dir = ".";
				break;
			case 'h':
				printf("%s", usage);
				exit(EXIT_SUCCESS);
			case 'l':
				if (!strcmp(optarg, "sim")) {
					log_sim = argv[optind];
					if ((!log_sim) || (*log_sim == '-')) {
						log_sim = "all";
					}
				} else if (!strcmp(optarg, "client")) {
					log_client = argv[optind];
					if ((!log_client) || (*log_client == '-')) {
						log_client = "all";
					}
				} else if (!strcmp(optarg, "general")) {
					log_general = "all";
				}
				break;
			case 'm':
				sim_monitor = atoi(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 's':
				password = optarg;
				break;
			case 't':
				if (sscanf(optarg, "%u", &watchdog_time) != 1) {
					watchdog_time = 60;
				}
				break;
			case 'u':
				user = optarg;
				break;
			case 'v':
				printf("%s: version=\"%s\"\n", prefix, VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 'w':
				if (sscanf(optarg, "%u", &wait_time) != 1) {
					wait_time = 0;
				}
				break;
			case 'x':
				sim_restart_flags |= SIM_RESTART_FLAG_SMS;
				break;
			default:
				printf("%s", usage);
				exit(EXIT_FAILURE);
		}
	}
	// check parameters for default
	if ((port < 1) || (port > 65535)) {
		port = default_port;
	}
	if (!user) {
		user = default_user;
	}
	if (!password) {
		password = default_password;
	}
	if (!ss9006_client_count) {
		ss9006_client_count = default_ss9006_client_count;
	}
	if (ss9006_client_count > TCP_SS9006_CLIENT_MAX_COUNT) {
		ss9006_client_count = TCP_SS9006_CLIENT_MAX_COUNT;
	}
	if (wait_time > 30) {
		wait_time = 30;
	}
	// prepare log path
	if (log_general) {
		if ((!mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
			snprintf(path, sizeof(path), "%s/general.log", log_dir);
			log_file = strdup(path);
			if (erase_dump) {
				unlink(path);
			}
		}
	}
	// check for daemonize
	if (daemonize) {
		// change current working directory
		if (chdir("/") < 0) {
			LOG("%s: can't change working directory to \"/\": %s\n", prefix, strerror(errno));
			goto main_end;
		}
		setbuf(stdout, 0);
		setbuf(stderr, 0);
		pid = -1;
		if ((pid = fork()) < 0) {
			LOG("%s: fork(): %s\n", prefix, strerror(errno));
			goto main_end;
		} else if (pid != 0) {
			// parent process
			exit(EXIT_SUCCESS);
		}
		// create new session to drop controlling tty terminal
		if (setsid() < 0) {
			LOG("%s: setsid(): %s\n", prefix, strerror(errno));
		}
		// try fork again to drop leader status in new process group
		pid = -1;
		if ((pid = fork()) < 0) {
			LOG("%s: fork(): %s\n", prefix, strerror(errno));
			goto main_end;
		} else if (pid != 0) {
			// parent process
			exit(EXIT_SUCCESS);
		}
		// create pid file
		pid = getpid();
		if ((fp = fopen(pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)pid);
			fclose(fp);
		} else {
			LOG("%s: can't create pid file \"%s\": %s\n", prefix, pid_file, strerror(errno));
			goto main_end;
		}
		if (!freopen("/dev/null", "r", stdin)) {
			LOG("%s: can't reopen \"%s\" file: %s\n", prefix, "stdin", strerror(errno));
			goto main_end;
		}
		if (!freopen("/dev/null", "w", stdout)) {
			LOG("%s: can't reopen \"%s\" file: %s\n", prefix, "stdout", strerror(errno));
			goto main_end;
		}
		if (!freopen("/dev/null", "w", stderr)) {
			LOG("%s: can't reopen \"%s\" file: %s\n", prefix, "stderr", strerror(errno));
			goto main_end;
		}
	}

	setbuf(stdout, 0);
	setbuf(stderr, 0);

	// register signal handler
	signal(SIGTERM, main_exit);
	signal(SIGINT, main_exit);
	signal(SIGSEGV, main_exit);
	signal(SIGALRM, main_exit);
	signal(SIGPIPE, SIG_IGN);

	LOG("%s: version \"%s\" started\n", prefix, VERSION);

	// clear SIM-card data
	memset(simcards, 0, sizeof(simcards));
	// init SIM-card data
	for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
		// reset client index
		simcards[i].client = -1;
		// prepare dump path
		if ((dump_sim) && (is_int_value_in_set(i, dump_sim))) {
			if ((!mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
				snprintf(path, sizeof(path), "%s/sim%03lu.dump", log_dir, (unsigned long int)i);
				simcards[i].dump = strdup(path);
				if (erase_dump) {
					unlink(path);
				}
			}
		}
		// prepare log path
		if ((log_sim) && (is_int_value_in_set(i, log_sim))) {
			if ((!mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
				snprintf(path, sizeof(path), "%s/sim%03lu.log", log_dir, (unsigned long int)i);
				simcards[i].log = strdup(path);
				if (erase_dump) {
					unlink(path);
				}
			}
		}
	}
	// alloc client storage
	if (!(tcp_ss9006_clients = calloc(ss9006_client_count, sizeof(struct tcp_ss9006_client)))) {
		LOG("%s: can't alloc memory for %lu clients\n", prefix, (unsigned long int)ss9006_client_count);
		goto main_end;
	}
	// init client data
	for (i = 0; i < ss9006_client_count; i++) {
		// prepare dump path
		if ((dump_client) && (is_int_value_in_set(i, dump_client))) {
			if ((!mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
				snprintf(path, sizeof(path), "%s/cli%03lu.dump", log_dir, (unsigned long int)i);
				tcp_ss9006_clients[i].dump = strdup(path);
				if (erase_dump) {
					unlink(path);
				}
			}
		}
		// prepare log path
		if ((log_client) && (is_int_value_in_set(i, log_client))) {
			if ((!mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
				snprintf(path, sizeof(path), "%s/cli%03lu.log", log_dir, (unsigned long int)i);
				tcp_ss9006_clients[i].log = strdup(path);
				if (erase_dump) {
					unlink(path);
				}
			}
		}
	}
	// set TCP server prefix
	snprintf(tcp_ss9006_prefix, sizeof(tcp_ss9006_prefix), "Server(%d)", port);
	// get TCP socket
	if ((tcp_ss9006_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		LOG("%s: socket(PF_INET, SOCK_STREAM, 0) failed - %s\n", tcp_ss9006_prefix, strerror(errno));
		goto main_end;
	}
	// set socket to non-block operation
	if ((tmp_flags = fcntl(tcp_ss9006_sock, F_GETFL)) < 0) {
		LOG("%s: fcntl(tcp_ss9006_sock, F_GETFL) failed - %s\n", tcp_ss9006_prefix, strerror(errno));
		goto main_end;
	}
	if (fcntl(tcp_ss9006_sock, F_SETFL, tmp_flags|O_NONBLOCK) < 0) {
		LOG("%s: fcntl(tcp_ss9006_sock, F_SETFL) failed - %s\n", tcp_ss9006_prefix, strerror(errno));
		goto main_end;
	}
	// set reuse address option
	tmp_opt = 1;
	if (setsockopt(tcp_ss9006_sock, SOL_SOCKET, SO_REUSEADDR, &tmp_opt, sizeof(tmp_opt)) < 0) {
		LOG("%s: setsockopt(tcp_ss9006_sock, SOL_SOCKET, SO_REUSEADDR) failed - %s\n", tcp_ss9006_prefix, strerror(errno));
		goto main_end;
	}
	// set server listen address
	memset(&tcp_ss9006_loc_addr, 0, sizeof(struct sockaddr_in));
	tcp_ss9006_loc_addr.sin_family = AF_INET;
	tcp_ss9006_loc_addr.sin_port = htons(port);
	tcp_ss9006_loc_addr.sin_addr.s_addr = ntohl(INADDR_ANY);
	tcp_ss9006_loc_addrlen = sizeof(struct sockaddr_in);
	if (bind(tcp_ss9006_sock, (struct sockaddr *)&tcp_ss9006_loc_addr, tcp_ss9006_loc_addrlen) < 0) {
		LOG("%s: bind() failed - %s\n", tcp_ss9006_prefix, strerror(errno));
		goto main_end;
	}
	// set server to listen
	if (listen(tcp_ss9006_sock, 4) < 0) {
		LOG("%s: listen() failed - %s\n", tcp_ss9006_prefix, strerror(errno));
		goto main_end;
	}
	// init tcp ss9006 client
	for (i = 0; i < ss9006_client_count; i++) {
		// socket
		tcp_ss9006_clients[i].sock = -1;
		// timers
		memset(&tcp_ss9006_clients[i].timers, 0, sizeof(tcp_ss9006_clients[i].timers));
		// flags
		memset(&tcp_ss9006_clients[i].flags, 0, sizeof(tcp_ss9006_clients[i].flags));
		// receiving buffer
		tcp_ss9006_clients[i].recv_length = 0;
		tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
		// transmiting buffer
		tcp_ss9006_clients[i].xmit_length = 0;
	}
	// open SIM-card devices
	for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
		// set SIM-card log prefix
		snprintf(simcards[i].prefix, sizeof(simcards[i].prefix), "SIM %03lu", (unsigned long int)i);
		// set SIM-card device path
		snprintf(path, sizeof(path), "/dev/simbank/sim%lu", (unsigned long int)i);
		if ((simcards[i].fd = open(path, O_RDWR | O_NONBLOCK)) < 0) {
			if (errno != ENOENT) {
				LOG("%s: can't open(%s) - %s\n", simcards[i].prefix, path, strerror(errno));
			}
		} else {
			if (sim_start == 0xff) {
				sim_start = i;
			}
			sim_end = i;
		}
	}
	// start existed SIM-card devices
	for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
		if (simcards[i].fd > 0) {
			// start enable timer
			x_timer_set_ms(simcards[i].timers.enable, i * 10);
			// stop rest timers
			x_timer_stop(simcards[i].timers.reset);
			x_timer_stop(simcards[i].timers.atr);
			x_timer_stop(simcards[i].timers.wait_time);
			x_timer_stop(simcards[i].timers.command);
			x_timer_stop(simcards[i].timers.status);
			// set flags
			simcards[i].flags.reset = 0;
			simcards[i].flags.reseting = 0;
			simcards[i].flags.inserted = 0;
			simcards[i].flags.busy = 0;
			simcards[i].flags.iccid = 0;
			simcards[i].flags.iccid_req = 1;
			simcards[i].flags.imsi = 0;
			simcards[i].flags.imsi_req = 1;
			simcards[i].flags.spn = 0;
			simcards[i].flags.spn_req = 1;
			simcards[i].flags.msisdn = 0;
			simcards[i].flags.msisdn_req = 1;
			simcards[i].flags.erase_sms = 0;
			if (sim_restart_flags & SIM_RESTART_FLAG_SMS) {
				simcards[i].flags.erase_sms_req = 1;
			}
		}
	}
	// main loop
	while (run) {
		for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
			if (simcards[i].fd > 0) {
				// timers
				// enable
				if (is_x_timer_enable(simcards[i].timers.enable) && is_x_timer_fired(simcards[i].timers.enable)) {
					// stop enable timer
					x_timer_stop(simcards[i].timers.enable);
					// set SIM-card state
					simcards[i].state = SIMBANK_SIMCARD_STATE_RESET;
					// reset SIM intreface devace
					iso_iec_7816_device_reset(&simcards[i].ifacedev, SIMBANK_SIMCARD_FREQUENCY);
					// enable SIM monitor
					if (sim_monitor == i) {
						sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_MONITOR;
						sc_write_data.header.length = sizeof(sc_write_data.container.monitor);
						sc_write_data.container.monitor = i;
						if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
							LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
							goto main_end;
						}
					}
					// set default speed
					sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_SPEED;
					sc_write_data.header.length = sizeof(sc_write_data.container.speed);
					sc_write_data.container.speed = 0x11;
					if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
						LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
						goto main_end;
					}
					// log
					if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
						dumptime(fp);
						fprintf(fp, "%s: Reset active\n", simcards[i].prefix);
						fclose(fp);
					}
					// led on
#ifdef SIMBANK_LED
					sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_LED;
					sc_write_data.header.length = sizeof(sc_write_data.container.led);
#if 0
					sc_write_data.container.led = 1;
#else
					sc_write_data.container.led = 0;
#endif
					if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
						LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
						goto main_end;
					}
#endif
					// apply reset signal
					sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_RESET;
					sc_write_data.header.length = sizeof(sc_write_data.container.reset);
					sc_write_data.container.reset = 0;
					if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
						LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
						goto main_end;
					}
					// start reset timer
					x_timer_set_ms(simcards[i].timers.reset, 500);
				}
				// reset
				if (is_x_timer_enable(simcards[i].timers.reset) && is_x_timer_fired(simcards[i].timers.reset)) {
					// stop reset timer
					x_timer_stop(simcards[i].timers.reset);
					// log
					if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
						dumptime(fp);
						fprintf(fp, "%s: Reset inactive\n", simcards[i].prefix);
						fclose(fp);
					}
					// led off
#ifdef SIMBANK_LED
					sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_LED;
					sc_write_data.header.length = sizeof(sc_write_data.container.led);
					sc_write_data.container.led = 0;
					if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
						LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
						goto main_end;
					}
#endif
					// release reset signal
					sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_RESET;
					sc_write_data.header.length = sizeof(sc_write_data.container.reset);
					sc_write_data.container.reset = 1;
					if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
						LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
						goto main_end;
					}
					// start atr timer
					x_timer_set_ms(simcards[i].timers.atr, 2000);
				}
				// atr
				if (is_x_timer_enable(simcards[i].timers.atr) && is_x_timer_fired(simcards[i].timers.atr)) {
					// stop atr timer
					x_timer_stop(simcards[i].timers.atr);
					// log
					if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
						dumptime(fp);
						fprintf(fp, "%s: ATR timer fired\n", simcards[i].prefix);
						fclose(fp);
					}
					if (simcards[i].flags.inserted) {
						simcards[i].flags.inserted = 0;
						LOG("%s: removed\n",simcards[i].prefix);
						// notify sim state
						for (k = 0; k < ss9006_client_count; k++) {
							if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
								tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 0, 0xff);
							}
						}
					}
					// restart SIM-card after 1000 ms
					simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
				}
				// wait_time
				if (is_x_timer_enable(simcards[i].timers.wait_time) && is_x_timer_fired(simcards[i].timers.wait_time)) {
					// stop wait_time timer
					x_timer_stop(simcards[i].timers.wait_time);
					// log
					if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
						dumptime(fp);
						fprintf(fp, "%s: Wait time timer fired\n", simcards[i].prefix);
						fclose(fp);
					}
					if (simcards[i].flags.inserted) {
						LOG("%s: Wait time timer fired\n", simcards[i].prefix);
						if (abort) {
							goto main_end;
						}
					}
					// restart SIM-card after 1000 ms
					simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
				}
				// command
				if (is_x_timer_enable(simcards[i].timers.command) && is_x_timer_fired(simcards[i].timers.command)) {
					// stop command timer
					x_timer_stop(simcards[i].timers.command);
					// log
					if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
						dumptime(fp);
						fprintf(fp, "%s: Command timer fired\n", simcards[i].prefix);
						fclose(fp);
					}
					if (simcards[i].flags.inserted) {
						LOG("%s: Command timer fired\n", simcards[i].prefix);
					}
					// restart SIM-card after 1000 ms
					simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
				}
				// status
				if (is_x_timer_enable(simcards[i].timers.status) && is_x_timer_fired(simcards[i].timers.status)) {
					// stop status timer
					x_timer_stop(simcards[i].timers.status);
#if 1
					// build SELECT command
					select_header[0] = 0xa0;
					select_header[1] = 0xa4;
					select_header[2] = 0x00;
					select_header[3] = 0x00;
					select_header[4] = 0x02;
					select_data[0] = 0x3f;
					select_data[1] = 0x00;
					iso_iec_7816_device_command_build(&simcards[i].ifacedev, select_header, CMD_WRITE|CMD_SERVICE, select_data, sizeof(select_data));
#else
					// build STATUS command
					status_header[0] = 0xa0;
					status_header[1] = 0xf2;
					status_header[2] = 0x00;
					status_header[3] = 0x00;
					status_header[4] = 0x0f;
					iso_iec_7816_device_command_build(&simcards[i].ifacedev, status_header, CMD_SERVICE, NULL, 0);
#endif
				}
			}
			// flags
			// reset
			if (simcards[i].flags.reset) {
				// restart SIM-card now
				simcard_restart(&simcards[i], 0, sim_restart_flags);
			}
			// command
			// write
			if ((simcards[i].state == SIMBANK_SIMCARD_STATE_IDLE) && (iso_iec_7816_device_command_is_sent(&simcards[i].ifacedev))) {
				simcards[i].ifacedev.command.flags &= ~CMD_SENT;
				// prepare container
				sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
				sc_write_data.header.length = sizeof(simcards[i].ifacedev.command.header);
				memcpy(sc_write_data.container.data, &simcards[i].ifacedev.command.header, sizeof(simcards[i].ifacedev.command.header));
				// dump
				if ((simcards[i].dump) && (fp = fopen(simcards[i].dump, "a"))) {
					dumptime(fp);
					fprintf(fp, "%s: Data write length=%u\n", simcards[i].prefix, sc_write_data.header.length);
					dumphex(fp, sc_write_data.container.data, sc_write_data.header.length);
					fclose(fp);
				}
#if 0
				// log
				if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
					dumptime(fp);
					fprintf(fp, "%s: Command header write\n", simcards[i].prefix);
					dumphex(fp, sc_write_data.container.data, sc_write_data.header.length);
					fclose(fp);
				}
#endif
				// write data
				if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
					LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
					goto main_end;
				} else {
					// start command timer
					x_timer_set_second(simcards[i].timers.command, 60);
					// start wait_time timer
					if (wait_time) {
						x_timer_set_second(simcards[i].timers.wait_time, wait_time);
					} else {
						x_timer_set_ns(simcards[i].timers.wait_time, simcards[i].ifacedev.WT);
					}
					// set SIM-card state
					simcards[i].state = SIMBANK_SIMCARD_STATE_RUN;
				}
			}
		}
		// traverse ss9006 clients
		for (i = 0; i < ss9006_client_count; i++) {
			// xmit data
			if (tcp_ss9006_clients[i].xmit_length) {
				// dump
				if ((tcp_ss9006_clients[i].dump) && (fp = fopen(tcp_ss9006_clients[i].dump, "a"))) {
					fprintf(fp, "%s: Data send length=%lu\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_clients[i].xmit_length);
					dumphex(fp, tcp_ss9006_clients[i].xmit_buf, tcp_ss9006_clients[i].xmit_length);
					fclose(fp);
				}
				// send data
				if (send(tcp_ss9006_clients[i].sock, tcp_ss9006_clients[i].xmit_buf, tcp_ss9006_clients[i].xmit_length, 0) < 0) {
					LOG("%s: send(tcp_ss9006_clients[i].sock) failed - %s\n", tcp_ss9006_clients[i].prefix, strerror(errno));
					// set close flag
					tcp_ss9006_clients[i].flags.close = 1;
				}
				tcp_ss9006_clients[i].xmit_length = 0;
			}
			// timers
			// auth
			if (is_x_timer_enable(tcp_ss9006_clients[i].timers.auth) && is_x_timer_fired(tcp_ss9006_clients[i].timers.auth)) {
				x_timer_stop(tcp_ss9006_clients[i].timers.auth);
				//
				LOG("%s: time for authorization expired\n", tcp_ss9006_clients[i].prefix);
				// set close flag
				tcp_ss9006_clients[i].flags.close = 1;
			}
			// watchdog
			if (is_x_timer_enable(tcp_ss9006_clients[i].timers.watchdog) && is_x_timer_fired(tcp_ss9006_clients[i].timers.watchdog)) {
				x_timer_stop(tcp_ss9006_clients[i].timers.watchdog);
				//
				LOG("%s: watchdog timer fired\n", tcp_ss9006_clients[i].prefix);
				// set close flag
				tcp_ss9006_clients[i].flags.close = 1;
			}
			// flags
			// close
			if (tcp_ss9006_clients[i].flags.close) {
				tcp_ss9006_clients[i].flags.close = 0;
				//
				LOG("%s: Connection with \"%s:%u\" closed\n", tcp_ss9006_prefix, inet_ntoa(tcp_ss9006_clients[i].addr.sin_addr), ntohs(tcp_ss9006_clients[i].addr.sin_port));
				// on close action
				x_timer_stop(tcp_ss9006_clients[i].timers.auth);
				x_timer_stop(tcp_ss9006_clients[i].timers.watchdog);
				close(tcp_ss9006_clients[i].sock);
				tcp_ss9006_clients[i].sock = -1;
				tcp_ss9006_clients[i].recv_length = 0;
				tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
				tcp_ss9006_clients[i].xmit_length = 0;
				// traverse SIM binded with this client
				for (j = 0; j < SIMBANK_SIMCARD_MAX; j++) {
					if (simcards[j].client == i) {
						// unbind SIM from this client
						simcards[j].client = -1;
						LOG("%s: Unbind SIM #%03lu succeeded\n", tcp_ss9006_clients[i].prefix, (long unsigned int)j);
						// start status timer
						x_timer_set_ms(simcards[j].timers.status, 0);
						// notify sim state
						for (k = 0; k < ss9006_client_count; k++) {
							if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
								tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, j, 1, 0xff);
								if (simcards[j].ifacedev.iccid_len) {
									tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[j].ifacedev.iccid_len, simcards[j].ifacedev.iccid);
								}
								if (simcards[j].ifacedev.spn_len) {
									tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[j].ifacedev.spn_len, simcards[j].ifacedev.spn);
								}
								if (simcards[j].ifacedev.msisdn_len) {
									tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[j].ifacedev.msisdn_len, simcards[j].ifacedev.msisdn);
								}
								if (simcards[j].ifacedev.imsi_len) {
									tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[j].ifacedev.imsi_len, simcards[j].ifacedev.imsi);
								}
							}
						}
					}
				}
				// notify client state
				for (j = 0; j < ss9006_client_count; j++) {
					if ((tcp_ss9006_clients[j].sock >= 0) && (tcp_ss9006_clients[j].flags.control)) {
						tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[j], SS9006_EXT_OPC_CLI_INFO, i, 0, 0);
					}
				}
			}
		}
		// prepare select
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;
		maxfd = 0;
		FD_ZERO(&rfds);
		for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
			if (simcards[i].fd > 0) {
				FD_SET(simcards[i].fd, &rfds);
				maxfd = mmax(simcards[i].fd, maxfd);
			}
		}
		if (tcp_ss9006_sock > 0) {
			FD_SET(tcp_ss9006_sock, &rfds);
			maxfd = mmax(tcp_ss9006_sock, maxfd);
		}
		for (i = 0; i < ss9006_client_count; i++) {
			if (tcp_ss9006_clients[i].sock > 0) {
				FD_SET(tcp_ss9006_clients[i].sock, &rfds);
				maxfd = mmax(tcp_ss9006_clients[i].sock, maxfd);
			}
		}
		res = select(maxfd + 1, &rfds, NULL, NULL, &timeout);
		if (res > 0) {
			for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
				if ((simcards[i].fd > 0) && (FD_ISSET(simcards[i].fd, &rfds))) {
					rlen = read(simcards[i].fd, &sc_read_data, sizeof(sc_read_data));
					if (rlen < 0) {
						LOG("%s: read() failed - %s\n", simcards[i].prefix, strerror(errno));
					} else if (rlen > 0) {
						// log
						if ((simcards[i].dump) && (fp = fopen(simcards[i].dump, "a"))) {
							dumptime(fp);
							fprintf(fp, "%s: Data read length=%u\n", simcards[i].prefix, sc_read_data.header.length);
							dumphex(fp, sc_read_data.container.data, sc_read_data.header.length);
							fclose(fp);
						}
						for (j = 0; j < sc_read_data.header.length; j++) {
							if (simcards[i].state == SIMBANK_SIMCARD_STATE_RESET) {
								if (iso_iec_7816_device_atr_read_byte(&simcards[i].ifacedev, sc_read_data.container.data[j]) < 0) {
									if (simcards[i].ifacedev.atr.length > 1) {
										LOG("%s: iso_iec_7816_device_atr_read_byte(0x%02x) failed\n", simcards[i].prefix, sc_read_data.container.data[j]);
										if (abort) {
											goto main_end;
										}
									}
									// restart SIM-card after 1000 ms
									simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
									break;
								} else {
									// restart wait_time timer
									if (wait_time) {
										x_timer_set_second(simcards[i].timers.wait_time, wait_time);
									} else {
										x_timer_set_ns(simcards[i].timers.wait_time, simcards[i].ifacedev.WT);
									}
									// check for complete
									if (iso_iec_7816_device_atr_is_complete(&simcards[i].ifacedev)) {
										// log
										if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
											dumptime(fp);
											fprintf(fp, "%s: ATR\n", simcards[i].prefix);
											dumphex(fp, simcards[i].ifacedev.atr.data, simcards[i].ifacedev.atr.length);
											fclose(fp);
										}
										// stop atr timer
										x_timer_stop(simcards[i].timers.atr);
										// stop wait_time timer
										x_timer_stop(simcards[i].timers.wait_time);
										// set SIM-card state
										simcards[i].state = SIMBANK_SIMCARD_STATE_IDLE;
										// check data rate
										switch (iso_iec_7816_device_atr_get_TA1(&simcards[i].ifacedev)) {
											case 0x94:
											case 0x95:
											case 0x96:
												// write PPS request data
												sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
												sc_write_data.header.length = iso_iec_7816_device_pps_request_build(&simcards[i].ifacedev, sc_write_data.container.data, 0, iso_iec_7816_device_atr_get_TA1(&simcards[i].ifacedev));
												// dump
												if ((simcards[i].dump) && (fp = fopen(simcards[i].dump, "a"))) {
													dumptime(fp);
													fprintf(fp, "%s: Data write length=%u\n", simcards[i].prefix, sc_write_data.header.length);
													dumphex(fp, sc_write_data.container.data, sc_write_data.header.length);
													fclose(fp);
												}
												// log
												if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
													dumptime(fp);
													fprintf(fp, "%s: PPS request\n", simcards[i].prefix);
													dumphex(fp, sc_write_data.container.data, sc_write_data.header.length);
													fclose(fp);
												}
												if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
													LOG("%s, write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
													goto main_end;
												} else {
													// start command timer
													x_timer_set_second(simcards[i].timers.command, 5);
													// start wait_time timer
													if (wait_time) {
														x_timer_set_second(simcards[i].timers.wait_time, wait_time);
													} else {
														x_timer_set_ns(simcards[i].timers.wait_time, simcards[i].ifacedev.WT);
													}
													// set SIM-card state
													simcards[i].state = SIMBANK_SIMCARD_STATE_PPS;
												}
												break;
											default:
												// set SIM-card flag to inserted
												if (!simcards[i].flags.inserted) {
													LOG("%s: inserted\n", simcards[i].prefix);
													// notify sim state
													for (k = 0; k < ss9006_client_count; k++) {
														if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
															tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 1, 0xff);
														}
													}
												}
												simcards[i].flags.inserted = 1;
												// check for SIM binding with client
												if (simcards[i].client < 0) {
													if (!simcards[i].flags.busy) {
														if (simcards[i].flags.iccid_req) {
															// run get iccid macro
															simcards[i].flags.iccid_req = 0;
															gsm_sim_cmd_get_iccid_sm(&simcards[i].ifacedev, 1);
															simcards[i].flags.iccid = 1;
															simcards[i].flags.busy = 1;
														} else if (simcards[i].flags.imsi_req) {
															// run get imsi macro
															simcards[i].flags.imsi_req = 0;
															gsm_sim_cmd_get_imsi_sm(&simcards[i].ifacedev, 1);
															simcards[i].flags.imsi = 1;
															simcards[i].flags.busy = 1;
														} else if (simcards[i].flags.spn_req) {
															// run get spn macro
															simcards[i].flags.spn_req = 0;
															gsm_sim_cmd_get_spn_sm(&simcards[i].ifacedev, 1);
															simcards[i].flags.spn = 1;
															simcards[i].flags.busy = 1;
														} else if (simcards[i].flags.msisdn_req) {
															// run get msisdn macro
															simcards[i].flags.msisdn_req = 0;
															gsm_sim_cmd_get_msisdn_sm(&simcards[i].ifacedev, 1);
															simcards[i].flags.msisdn = 1;
															simcards[i].flags.busy = 1;
														} else if (simcards[i].flags.erase_sms_req) {
															// run erase sms macro
															simcards[i].flags.erase_sms_req = 0;
															gsm_sim_cmd_erase_sms_sm(&simcards[i].ifacedev, 1);
															simcards[i].flags.erase_sms = 1;
															simcards[i].flags.busy = 1;
														} else {
															// start status timer
															x_timer_set_ms(simcards[i].timers.status, 0);
														}
													}
												} else if (simcards[i].flags.reseting) {
													simcards[i].flags.reseting = 0;
													// prepare reset response
													LOG("%s: Reset SIM #%03lu response\n", tcp_ss9006_clients[simcards[i].client].prefix, (long unsigned int)i);
													tcp_ss9006_sim_reset_response = (struct ss9006_sim_reset_response *)&tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length];
													tcp_ss9006_sim_reset_response->hexfd = SS9006_OPC_SIM_RESET;
													tcp_ss9006_sim_reset_response->sim = i;
													tcp_ss9006_sim_reset_response->reserved = 1;
													tcp_ss9006_sim_reset_response->length = simcards[i].ifacedev.atr.length + 1;
													tmpu16 = 0;
													for (j = 0; j < simcards[i].ifacedev.atr.length; j++) {
														tmpu16 += simcards[i].ifacedev.atr.data[j];
													}
													tcp_ss9006_sim_reset_response->crc = htons(tmpu16);
													memcpy(tcp_ss9006_sim_reset_response->atr, simcards[i].ifacedev.atr.data, simcards[i].ifacedev.atr.length);
													tcp_ss9006_clients[simcards[i].client].xmit_length += sizeof(struct ss9006_sim_reset_response) - sizeof(tcp_ss9006_sim_reset_response->atr) + simcards[i].ifacedev.atr.length;
												}
												break;
										}
									}
								}
							} else if (simcards[i].state == SIMBANK_SIMCARD_STATE_PPS) {
								if (iso_iec_7816_device_pps_read_byte(&simcards[i].ifacedev, sc_read_data.container.data[j]) < 0) {
									LOG("%s: iso_iec_7816_device_pps_read_byte(0x%02x) failed\n", simcards[i].prefix, sc_read_data.container.data[j]);
									if (abort) {
										goto main_end;
									}
									// restart SIM-card after 1000 ms
									simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
									break;
								} else {
									// restart wait_time timer
									if (wait_time) {
										x_timer_set_second(simcards[i].timers.wait_time, wait_time);
									} else {
										x_timer_set_ns(simcards[i].timers.wait_time, simcards[i].ifacedev.WT);
									}
									// check for complete
									if (iso_iec_7816_device_pps_is_complete(&simcards[i].ifacedev)) {
										// log
										if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
											dumptime(fp);
											fprintf(fp, "%s: PPS response\n", simcards[i].prefix);
											dumphex(fp, simcards[i].ifacedev.pps.data, simcards[i].ifacedev.pps.length);
											fclose(fp);
										}
										// adjust guard and wait time
										iso_iec_7816_device_apply_data_rate(&simcards[i].ifacedev, simcards[i].ifacedev.pps.pps0 & 0xf, simcards[i].ifacedev.pps.pps1);
										// set negotiated data rate
										sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_SPEED;
										sc_write_data.header.length = sizeof(sc_write_data.container.speed);
										sc_write_data.container.speed = simcards[i].ifacedev.pps.pps1;
										if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
											LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
											goto main_end;
										}
										// stop command timer
										x_timer_stop(simcards[i].timers.command);
										// stop wait_time timer
										x_timer_stop(simcards[i].timers.wait_time);
										// set SIM-card state
										simcards[i].state = SIMBANK_SIMCARD_STATE_IDLE;
										// set SIM-card flag to inserted
										if (!simcards[i].flags.inserted) {
											LOG("%s: inserted\n", simcards[i].prefix);
											// notify sim state
											for (k = 0; k < ss9006_client_count; k++) {
												if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
													tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 1, 0xff);
												}
											}
										}
										simcards[i].flags.inserted = 1;
										// check for SIM binding with client
										if (simcards[i].client < 0) {
											if (!simcards[i].flags.busy) {
												if (simcards[i].flags.iccid_req) {
													// run get iccid macro
													simcards[i].flags.iccid_req = 0;
													gsm_sim_cmd_get_iccid_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.iccid = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.imsi_req) {
													// run get imsi macro
													simcards[i].flags.imsi_req = 0;
													gsm_sim_cmd_get_imsi_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.imsi = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.spn_req) {
													// run get spn macro
													simcards[i].flags.spn_req = 0;
													gsm_sim_cmd_get_spn_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.spn = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.msisdn_req) {
													// run get msisdn macro
													simcards[i].flags.msisdn_req = 0;
													gsm_sim_cmd_get_msisdn_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.msisdn = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.erase_sms_req) {
													// run erase sms macro
													simcards[i].flags.erase_sms_req = 0;
													gsm_sim_cmd_erase_sms_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.erase_sms = 1;
													simcards[i].flags.busy = 1;
												} else {
													// start status timer
													x_timer_set_ms(simcards[i].timers.status, 0);
												}
											}
										} else if (simcards[i].flags.reseting) {
											simcards[i].flags.reseting = 0;
											// prepare reset response
											LOG("%s: Reset SIM #%03lu response\n", tcp_ss9006_clients[simcards[i].client].prefix, (long unsigned int)i);
											tcp_ss9006_sim_reset_response = (struct ss9006_sim_reset_response *)&tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length];
											tcp_ss9006_sim_reset_response->hexfd = SS9006_OPC_SIM_RESET;
											tcp_ss9006_sim_reset_response->sim = i;
											tcp_ss9006_sim_reset_response->reserved = 1;
											tcp_ss9006_sim_reset_response->length = simcards[i].ifacedev.atr.length + 1;
											tmpu16 = 0;
											for (j = 0; j < simcards[i].ifacedev.atr.length; j++) {
												tmpu16 += simcards[i].ifacedev.atr.data[j];
											}
											tcp_ss9006_sim_reset_response->crc = htons(tmpu16);
											memcpy(tcp_ss9006_sim_reset_response->atr, simcards[i].ifacedev.atr.data, simcards[i].ifacedev.atr.length);
											tcp_ss9006_clients[simcards[i].client].xmit_length += sizeof(struct ss9006_sim_reset_response) - sizeof(tcp_ss9006_sim_reset_response->atr) + simcards[i].ifacedev.atr.length;
										}
									}
								}
							} else if (simcards[i].state == SIMBANK_SIMCARD_STATE_RUN) {
								if (iso_iec_7816_device_command_read_byte(&simcards[i].ifacedev, sc_read_data.container.data[j]) < 0) {
									LOG("%s: iso_iec_7816_device_command_read_byte(0x%02x) failed\n", simcards[i].prefix, sc_read_data.container.data[j]);
									if (abort) {
										goto main_end;
									}
									// restart SIM-card after 1000 ms
									simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
									break;
								} else {
									// restart wait_time timer
									if (wait_time) {
										x_timer_set_second(simcards[i].timers.wait_time, wait_time);
									} else {
										x_timer_set_ns(simcards[i].timers.wait_time, simcards[i].ifacedev.WT);
									}
									// check for complete
									if (iso_iec_7816_device_command_is_complete(&simcards[i].ifacedev)) {
#if 0
										// log
										if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
											dumptime(fp);
											if (simcards[i].ifacedev.command.length_rd) {
												fprintf(fp, "%s: Command data read\n", simcards[i].prefix);
												dumphex(fp, simcards[i].ifacedev.command.data_rd, simcards[i].ifacedev.command.length_rd);
											}
											fprintf(fp, "%s: Command status %02x %02x\n", simcards[i].prefix, simcards[i].ifacedev.command.sw1, simcards[i].ifacedev.command.sw2);
											fclose(fp);
										}
#endif
										// stop command timer
										x_timer_stop(simcards[i].timers.command);
										// stop wait_time timer
										x_timer_stop(simcards[i].timers.wait_time);
										// set SIM-card state
										simcards[i].state = SIMBANK_SIMCARD_STATE_IDLE;
										// check for SIM binding with client
										if (simcards[i].client < 0 ) {
											if (simcards[i].flags.iccid) {
												// run get iccid macro
												if (gsm_sim_cmd_get_iccid_sm(&simcards[i].ifacedev, 0)) {
													LOG("%s: gsm_sim_cmd_get_iccid_sm() failed\n", simcards[i].prefix);
													if (abort) {
														goto main_end;
													} 
													// restart SIM-card after 1000 ms
													simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
													break;
												} else if (gsm_sim_cmd_is_done(&simcards[i].ifacedev)) {
													if (simcards[i].ifacedev.iccid_len) {
														LOG("%s: ICCID=\"%.*s\"\n", simcards[i].prefix, (int)simcards[i].ifacedev.iccid_len, simcards[i].ifacedev.iccid);
														// notify sim ICCID
														for (k = 0; k < ss9006_client_count; k++) {
															if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
																tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 1, 0xff);
																if (simcards[i].ifacedev.iccid_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[i].ifacedev.iccid_len, simcards[i].ifacedev.iccid);
																}
																if (simcards[i].ifacedev.spn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[i].ifacedev.spn_len, simcards[i].ifacedev.spn);
																}
																if (simcards[i].ifacedev.msisdn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[i].ifacedev.msisdn_len, simcards[i].ifacedev.msisdn);
																}
																if (simcards[i].ifacedev.imsi_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[i].ifacedev.imsi_len, simcards[i].ifacedev.imsi);
																}
															}
														}
													}
													//
													simcards[i].flags.iccid = 0;
													simcards[i].flags.busy = 0;
												}
											}
											if (simcards[i].flags.imsi) {
												// run get iccid macro
												if (gsm_sim_cmd_get_imsi_sm(&simcards[i].ifacedev, 0)) {
													LOG("%s: gsm_sim_cmd_get_imsi_sm() failed\n", simcards[i].prefix);
													if (abort) {
														goto main_end;
													} 
													// restart SIM-card after 1000 ms
													simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
													break;
												} else if (gsm_sim_cmd_is_done(&simcards[i].ifacedev)) {
													if (simcards[i].ifacedev.imsi_len) {
														LOG("%s: IMSI=\"%.*s\"\n", simcards[i].prefix, (int)simcards[i].ifacedev.imsi_len, simcards[i].ifacedev.imsi);
														// notify sim IMSI
														for (k = 0; k < ss9006_client_count; k++) {
															if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
																tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 1, 0xff);
																if (simcards[i].ifacedev.iccid_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[i].ifacedev.iccid_len, simcards[i].ifacedev.iccid);
																}
																if (simcards[i].ifacedev.spn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[i].ifacedev.spn_len, simcards[i].ifacedev.spn);
																}
																if (simcards[i].ifacedev.msisdn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[i].ifacedev.msisdn_len, simcards[i].ifacedev.msisdn);
																}
																if (simcards[i].ifacedev.imsi_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[i].ifacedev.imsi_len, simcards[i].ifacedev.imsi);
																}
															}
														}
													}
													//
													simcards[i].flags.imsi = 0;
													simcards[i].flags.busy = 0;
												}
											}
											if (simcards[i].flags.spn) {
												// run get spn macro
												if (gsm_sim_cmd_get_spn_sm(&simcards[i].ifacedev, 0)) {
													LOG("%s: gsm_sim_cmd_get_spn_sm() failed\n", simcards[i].prefix);
													if (abort) {
														goto main_end;
													} 
													// restart SIM-card after 1000 ms
													simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
													break;
												} else if (gsm_sim_cmd_is_done(&simcards[i].ifacedev)) {
													if (simcards[i].ifacedev.spn_len) {
														LOG("%s: SPN=\"%.*s\"\n", simcards[i].prefix, (int)simcards[i].ifacedev.spn_len, simcards[i].ifacedev.spn);
														// notify sim SPN
														for (k = 0; k < ss9006_client_count; k++) {
															if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
																tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 1, 0xff);
																if (simcards[i].ifacedev.iccid_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[i].ifacedev.iccid_len, simcards[i].ifacedev.iccid);
																}
																if (simcards[i].ifacedev.spn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[i].ifacedev.spn_len, simcards[i].ifacedev.spn);
																}
																if (simcards[i].ifacedev.msisdn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[i].ifacedev.msisdn_len, simcards[i].ifacedev.msisdn);
																}
																if (simcards[i].ifacedev.imsi_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[i].ifacedev.imsi_len, simcards[i].ifacedev.imsi);
																}
															}
														}
													}
													//
													simcards[i].flags.spn = 0;
													simcards[i].flags.busy = 0;
												}
											}
											if (simcards[i].flags.msisdn) {
												// run get msisdn macro
												if (gsm_sim_cmd_get_msisdn_sm(&simcards[i].ifacedev, 0)) {
													LOG("%s: gsm_sim_cmd_get_msisdn_sm() failed\n", simcards[i].prefix);
													if (abort) {
														goto main_end;
													} 
													// restart SIM-card after 1000 ms
													simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
													break;
												} else if (gsm_sim_cmd_is_done(&simcards[i].ifacedev)) {
													if (simcards[i].ifacedev.msisdn_len) {
														LOG("%s: MSISDN=\"%.*s\"\n", simcards[i].prefix, (int)simcards[i].ifacedev.msisdn_len, simcards[i].ifacedev.msisdn);
														// notify sim MSISDN
														for (k = 0; k < ss9006_client_count; k++) {
															if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
																tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, i, 1, 0xff);
																if (simcards[i].ifacedev.iccid_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[i].ifacedev.iccid_len, simcards[i].ifacedev.iccid);
																}
																if (simcards[i].ifacedev.spn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[i].ifacedev.spn_len, simcards[i].ifacedev.spn);
																}
																if (simcards[i].ifacedev.msisdn_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[i].ifacedev.msisdn_len, simcards[i].ifacedev.msisdn);
																}
																if (simcards[i].ifacedev.imsi_len) {
																	tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[i].ifacedev.imsi_len, simcards[i].ifacedev.imsi);
																}
															}
														}
													}
													//
													simcards[i].flags.msisdn = 0;
													simcards[i].flags.busy = 0;
												}
											}
											if (simcards[i].flags.erase_sms) {
												// run erase sms macro
												if (gsm_sim_cmd_erase_sms_sm(&simcards[i].ifacedev, 0)) {
													LOG("%s: gsm_sim_cmd_erase_sms_sm() failed\n", simcards[i].prefix);
													if (abort) {
														goto main_end;
													} 
													// restart SIM-card after 1000 ms
													simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
													break;
												} else if (gsm_sim_cmd_is_done(&simcards[i].ifacedev)) {
													simcards[i].flags.erase_sms = 0;
													simcards[i].flags.busy = 0;
												}
											}
											if (!simcards[i].flags.busy) {
												if (simcards[i].flags.iccid_req) {
													// run get iccid macro
													simcards[i].flags.iccid_req = 0;
													gsm_sim_cmd_get_iccid_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.iccid = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.imsi_req) {
													// run get imsi macro
													simcards[i].flags.imsi_req = 0;
													gsm_sim_cmd_get_imsi_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.imsi = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.spn_req) {
													// run get spn macro
													simcards[i].flags.spn_req = 0;
													gsm_sim_cmd_get_spn_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.spn = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.msisdn_req) {
													// run get msisdn macro
													simcards[i].flags.msisdn_req = 0;
													gsm_sim_cmd_get_msisdn_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.msisdn = 1;
													simcards[i].flags.busy = 1;
												} else if (simcards[i].flags.erase_sms_req) {
													// run erase sms macro
													simcards[i].flags.erase_sms_req = 0;
													gsm_sim_cmd_erase_sms_sm(&simcards[i].ifacedev, 1);
													simcards[i].flags.erase_sms = 1;
													simcards[i].flags.busy = 1;
												} else {
													// start status timer
													x_timer_set_ms(simcards[i].timers.status, 1000);
												}
											}
										} else {
											if (!iso_iec_7816_device_command_is_service(&simcards[i].ifacedev)) {
												// prepare command response
												tcp_ss9006_combined_header = (struct ss9006_combined_header *)&tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length];
												tcp_ss9006_combined_header->cmd = SS9006_OPC_COMBINED;
												tcp_ss9006_combined_header->length = sizeof(struct ss9006_combined_chunk_header) + simcards[i].ifacedev.command.length_rd + 2;
												tcp_ss9006_clients[simcards[i].client].xmit_length += sizeof(struct ss9006_combined_header);
												tcp_ss9006_combined_chunk_header = (struct ss9006_combined_chunk_header *)&tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length];
												tcp_ss9006_combined_chunk_header->sim = i;
												tcp_ss9006_combined_chunk_header->length = simcards[i].ifacedev.command.length_rd + 2;
												tcp_ss9006_clients[simcards[i].client].xmit_length += sizeof(struct ss9006_combined_chunk_header);
												if (simcards[i].ifacedev.command.length_rd) {
													memcpy(&tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length], simcards[i].ifacedev.command.data_rd, simcards[i].ifacedev.command.length_rd);
													tcp_ss9006_clients[simcards[i].client].xmit_length += simcards[i].ifacedev.command.length_rd;
												}
												tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length + 0] = simcards[i].ifacedev.command.sw1;
												tcp_ss9006_clients[simcards[i].client].xmit_buf[tcp_ss9006_clients[simcards[i].client].xmit_length + 1] = simcards[i].ifacedev.command.sw2;
												tcp_ss9006_clients[simcards[i].client].xmit_length += 2;
											}
										}
									} else if (iso_iec_7816_device_command_is_acknowledge(&simcards[i].ifacedev, sc_read_data.container.data[j])) {
										if (iso_iec_7816_device_command_is_write(&simcards[i].ifacedev)) {
											// write command data
											sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
											sc_write_data.header.length = simcards[i].ifacedev.command.length_wr;
											memcpy(sc_write_data.container.data, simcards[i].ifacedev.command.data_wr, simcards[i].ifacedev.command.length_wr);
											// dump
											if ((simcards[i].dump) && (fp = fopen(simcards[i].dump, "a"))) {
												dumptime(fp);
												fprintf(fp, "%s: Data write length=%u\n", simcards[i].prefix, sc_write_data.header.length);
												dumphex(fp, sc_write_data.container.data, sc_write_data.header.length);
												fclose(fp);
											}
#if 0
											// log
											if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
												dumptime(fp);
												fprintf(fp, "%s: Command data write\n", simcards[i].prefix);
												dumphex(fp, sc_write_data.container.data, sc_write_data.header.length);
												fclose(fp);
											}
#endif
											// write data
											if (write(simcards[i].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length) < 0) {
												LOG("%s: write(dev_fd): %s\n", simcards[i].prefix, strerror(errno));
												goto main_end;
											}
										}
									}
								}
							} else {
								// log
								if ((simcards[i].log) && (fp = fopen(simcards[i].log, "a"))) {
									dumptime(fp);
									fprintf(fp, "%s: read unexpected data length=%lu\n", simcards[i].prefix, (unsigned long int)(sc_read_data.header.length - j));
									dumphex(fp, &sc_read_data.container.data[j], sc_read_data.header.length - j);
									fclose(fp);
								}
								if (simcards[i].flags.inserted) {
									LOG("%s: read unexpected data length=%lu\n", simcards[i].prefix, (unsigned long int)(sc_read_data.header.length - j));
									if (abort) {
										goto main_end;
									}
								}
								// restart SIM-card after 1000 ms
								simcard_restart(&simcards[i], 1000, sim_restart_flags | SIM_RESTART_FLAG_CLI);
								break;
							}
						}
					}
				}
			}
			// tcp ss9006 socket
			if ((tcp_ss9006_sock > 0) && (FD_ISSET(tcp_ss9006_sock, &rfds))) {
				tcp_ss9006_rem_addrlen = sizeof(tcp_ss9006_rem_addr);
				if ((res = accept(tcp_ss9006_sock, (struct sockaddr *)&tcp_ss9006_rem_addr, &tcp_ss9006_rem_addrlen)) < 0) {
					LOG("%s: accept(tcp_ss9006_sock) failed - %s\n", tcp_ss9006_prefix, strerror(errno));
				} else {
					// set socket to non-block operation
					if ((tmp_flags = fcntl(res, F_GETFL)) < 0) {
						LOG("%s: Discard connection from \"%s:%u\" - fcntl(res, F_GETFL) failed - %s\n", tcp_ss9006_prefix, inet_ntoa(tcp_ss9006_rem_addr.sin_addr), ntohs(tcp_ss9006_rem_addr.sin_port), strerror(errno));
						close(res);
					} else if (fcntl(res, F_SETFL, tmp_flags|O_NONBLOCK) < 0) {
						LOG("%s: Discard connection from \"%s:%u\" - fcntl(res, F_SETFL) failed - %s\n", tcp_ss9006_prefix, inet_ntoa(tcp_ss9006_rem_addr.sin_addr), ntohs(tcp_ss9006_rem_addr.sin_port), strerror(errno));
						close(res);
					} else {
						// traverse clients slot
						for (i = 0; i < ss9006_client_count; i++) {
							// check slot for busy
							if (tcp_ss9006_clients[i].sock < 0) {
								// accept new client connection
								LOG("%s: Connection from \"%s:%u\" accepted\n", tcp_ss9006_prefix, inet_ntoa(tcp_ss9006_rem_addr.sin_addr), ntohs(tcp_ss9006_rem_addr.sin_port));
								// copy client data
								tcp_ss9006_clients[i].sock = res;
								memcpy(&tcp_ss9006_clients[i].addr, &tcp_ss9006_rem_addr, tcp_ss9006_rem_addrlen);
								tcp_ss9006_clients[i].addrlen = tcp_ss9006_rem_addrlen;
								// set TCP client prefix
								snprintf(tcp_ss9006_clients[i].prefix, sizeof(tcp_ss9006_clients[i].prefix), "Client(%s:%u)", inet_ntoa(tcp_ss9006_clients[i].addr.sin_addr), ntohs(tcp_ss9006_clients[i].addr.sin_port));
								// init TCP client data buffer
								tcp_ss9006_clients[i].recv_length = 0;
								tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
								tcp_ss9006_clients[i].xmit_length = 0;
								// start auth timer
								x_timer_set_second(tcp_ss9006_clients[i].timers.auth, 5);
								// start watchdog timer
								if (watchdog_time) {
									x_timer_set_second(tcp_ss9006_clients[i].timers.watchdog, watchdog_time);
								}
								// notify client state
								for (j = 0; j < ss9006_client_count; j++) {
									if ((tcp_ss9006_clients[j].sock >= 0) && (tcp_ss9006_clients[j].flags.control) && (i != j)) {
										tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[j], SS9006_EXT_OPC_CLI_INFO, i, 1, 0);
										tcp_ss9006_cli_msg_ext_add_param_string(&tcp_ss9006_clients[j], 0, "%s", inet_ntoa(tcp_ss9006_clients[i].addr.sin_addr));
										tcp_ss9006_cli_msg_ext_add_param_string(&tcp_ss9006_clients[j], 1, "%u", ntohs(tcp_ss9006_clients[i].addr.sin_port));
									}
								}
								break;
							}
						}
						if (i == ss9006_client_count) {
							LOG("%s: Discard connection from \"%s:%u\" - free slot not found\n", tcp_ss9006_prefix, inet_ntoa(tcp_ss9006_rem_addr.sin_addr), ntohs(tcp_ss9006_rem_addr.sin_port));
							close(res);
						}
					}
				}
			}
			// tcp ss9006 client socket
			for (i = 0; i < ss9006_client_count; i++) {
				if ((tcp_ss9006_clients[i].sock > 0) && (FD_ISSET(tcp_ss9006_clients[i].sock, &rfds))) {
					res = recv(tcp_ss9006_clients[i].sock, &tcp_ss9006_clients[i].recv_buf[tcp_ss9006_clients[i].recv_length], tcp_ss9006_clients[i].recv_wait - tcp_ss9006_clients[i].recv_length, 0);
					if (res > 0) {
						// restart watchdog timer
						if (watchdog_time) {
							x_timer_set_second(tcp_ss9006_clients[i].timers.watchdog, watchdog_time);
						}
						// dump
						if ((tcp_ss9006_clients[i].dump) && (fp = fopen(tcp_ss9006_clients[i].dump, "a"))) {
							fprintf(fp, "%s: Data received length=%lu\n", tcp_ss9006_clients[i].prefix, (unsigned long int)res);
							dumphex(fp, &tcp_ss9006_clients[i].recv_buf[tcp_ss9006_clients[i].recv_length], res);
							fclose(fp);
						}
						tcp_ss9006_clients[i].recv_length += res;
						//
						tcp_ss9006_base_header = (struct ss9006_base_header *)tcp_ss9006_clients[i].recv_buf;
						switch (tcp_ss9006_base_header->opc) {
							case SS9006_OPC_AUTHORIZATION:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_authorization_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_authorization_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_authorization_request)) {
										tcp_ss9006_authorization_request = (struct ss9006_authorization_request *)tcp_ss9006_clients[i].recv_buf;
										tmpu16 = 0;
										for (j = 0; j < sizeof(tcp_ss9006_authorization_request->user); j++) {
											tmpu16 += tcp_ss9006_authorization_request->user[j];
											if (tcp_ss9006_authorization_request->user[j] == 0x20) {
												tcp_ss9006_authorization_request->user[j] = 0x00;
											}
										}
										for (j = 0; j < sizeof(tcp_ss9006_authorization_request->password); j++) {
											tmpu16 += tcp_ss9006_authorization_request->password[j];
											if (tcp_ss9006_authorization_request->password[j] == 0x20) {
												tcp_ss9006_authorization_request->password[j] = 0x00;
											}
										}
										// verify checksum
										if (tcp_ss9006_authorization_request->checksum == tmpu16) {
											if (!strcmp((char *)tcp_ss9006_authorization_request->user, user) && !strcmp((char *)tcp_ss9006_authorization_request->password, password)) {
												// successfull authorization
												LOG("%s: Authorization succeeded\n", tcp_ss9006_clients[i].prefix);
												// prepare successfull authorization response
												tcp_ss9006_authorization_response = (struct ss9006_authorization_response *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
												tcp_ss9006_authorization_response->hex01 = SS9006_OPC_AUTHORIZATION;
												tcp_ss9006_authorization_response->status = 0;
												tcp_ss9006_authorization_response->reserved = 1;
												tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_authorization_response);
												// stop auth timer
												x_timer_stop(tcp_ss9006_clients[i].timers.auth);
											} else {
												// login incorrect
												LOG("%s: Authorization failed: login incorrect\n", tcp_ss9006_clients[i].prefix);
												// prepare failure authorization response
												tcp_ss9006_authorization_response = (struct ss9006_authorization_response *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
												tcp_ss9006_authorization_response->hex01 = SS9006_OPC_AUTHORIZATION;
												tcp_ss9006_authorization_response->status = 6;
												tcp_ss9006_authorization_response->reserved = 1;
												tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_authorization_response);
												// set close flag
												tcp_ss9006_clients[i].flags.close = 1;
											}
										} else {
											// bad checksum
											LOG("%s: Authorization failed: bad checksum received=0x%04x - calculated=0x%04x\n", tcp_ss9006_clients[i].prefix, tcp_ss9006_authorization_request->checksum, tmpu16);
											// prepare failure authorization response
											tcp_ss9006_authorization_response = (struct ss9006_authorization_response *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
											tcp_ss9006_authorization_response->hex01 = SS9006_OPC_AUTHORIZATION;
											tcp_ss9006_authorization_response->status = 6;
											tcp_ss9006_authorization_response->reserved = 1;
											tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_authorization_response);
											// set close flag
											tcp_ss9006_clients[i].flags.close = 1;
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_COMBINED:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_combined_header)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_combined_header);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_combined_header)) {
										tcp_ss9006_combined_header = (struct ss9006_combined_header *)tcp_ss9006_clients[i].recv_buf;
										// check for full length
										if (tcp_ss9006_clients[i].recv_wait < (sizeof(struct ss9006_combined_header) + tcp_ss9006_combined_header->length)) {
											tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_combined_header) + tcp_ss9006_combined_header->length;
										} else {
											if (tcp_ss9006_clients[i].recv_length >= (sizeof(struct ss9006_combined_header) + tcp_ss9006_combined_header->length)) {
												// traverse all data chunks
												for (j = sizeof(struct ss9006_combined_header); j < sizeof(struct ss9006_combined_header) + tcp_ss9006_combined_header->length; ) {
													tcp_ss9006_combined_chunk_header = (struct ss9006_combined_chunk_header *)&tcp_ss9006_clients[i].recv_buf[j];
													j += sizeof(struct ss9006_combined_chunk_header);
													if (tcp_ss9006_combined_chunk_header->length) {
														// check for valid SIM index
														if (tcp_ss9006_combined_chunk_header->sim < SIMBANK_SIMCARD_MAX) {
															// check for SIM insertion status
															if (simcards[tcp_ss9006_combined_chunk_header->sim].flags.inserted) {
																// check for SIM binding
																if (simcards[tcp_ss9006_combined_chunk_header->sim].client == i) {
																	// check for SIM command state
																	if (simcards[tcp_ss9006_combined_chunk_header->sim].state == SIMBANK_SIMCARD_STATE_IDLE) {
																		// this -- check for supported command class
																		if ((tcp_ss9006_clients[i].recv_buf[j] & 0xf0) == 0x00) {
																			// select read/write command type
																			if (get_iso_iec_7816_cla0x_ins_type(tcp_ss9006_clients[i].recv_buf[j + 1]) < 0) {
																				// read
																				iso_iec_7816_device_command_build(&simcards[tcp_ss9006_combined_chunk_header->sim].ifacedev, &tcp_ss9006_clients[i].recv_buf[j], 0, NULL, 0);
																			} else if (get_iso_iec_7816_cla0x_ins_type(tcp_ss9006_clients[i].recv_buf[j + 1]) > 0) {
																				// write
																				iso_iec_7816_device_command_build(&simcards[tcp_ss9006_combined_chunk_header->sim].ifacedev, &tcp_ss9006_clients[i].recv_buf[j], CMD_WRITE, &tcp_ss9006_clients[i].recv_buf[j+5], tcp_ss9006_combined_chunk_header->length - 5);
																			} else {
																				// unknown
																				LOG("%s: Command to SIM #%03lu failed - unknown command=0x%02x from class=0x%02x\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim, tcp_ss9006_clients[i].recv_buf[j], tcp_ss9006_clients[i].recv_buf[j + 1]);
																				// prepare command response
																				tcp_ss9006_combined_header = (struct ss9006_combined_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																				tcp_ss9006_combined_header->cmd = SS9006_OPC_COMBINED;
																				tcp_ss9006_combined_header->length = sizeof(struct ss9006_combined_chunk_header) + 2;
																				tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_header);
																				tcp_ss9006_combined_chunk_header = (struct ss9006_combined_chunk_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																				tcp_ss9006_combined_chunk_header->sim = i;
																				tcp_ss9006_combined_chunk_header->length = 2;
																				tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_chunk_header);
																				tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 0] = 0x6d;
																				tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 1] = 0x00;
																				tcp_ss9006_clients[i].xmit_length += 2;
																			}
																		} else if ((tcp_ss9006_clients[i].recv_buf[j] & 0xf0) == 0x80) {
																			if (get_3gpp_ts_101_221_cla8x_ins_type(tcp_ss9006_clients[i].recv_buf[j + 1]) < 0) {
																				// read
																				iso_iec_7816_device_command_build(&simcards[tcp_ss9006_combined_chunk_header->sim].ifacedev, &tcp_ss9006_clients[i].recv_buf[j], 0, NULL, 0);
																			} else if (get_3gpp_ts_101_221_cla8x_ins_type(tcp_ss9006_clients[i].recv_buf[j + 1]) > 0) {
																				// write
																				iso_iec_7816_device_command_build(&simcards[tcp_ss9006_combined_chunk_header->sim].ifacedev, &tcp_ss9006_clients[i].recv_buf[j], CMD_WRITE, &tcp_ss9006_clients[i].recv_buf[j+5], tcp_ss9006_combined_chunk_header->length - 5);
																			} else {
																				// unknown
																				LOG("%s: Command to SIM #%03lu failed - unknown command=0x%02x from class=0x%02x\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim, tcp_ss9006_clients[i].recv_buf[j], tcp_ss9006_clients[i].recv_buf[j + 1]);
																				// prepare command response
																				tcp_ss9006_combined_header = (struct ss9006_combined_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																				tcp_ss9006_combined_header->cmd = SS9006_OPC_COMBINED;
																				tcp_ss9006_combined_header->length = sizeof(struct ss9006_combined_chunk_header) + 2;
																				tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_header);
																				tcp_ss9006_combined_chunk_header = (struct ss9006_combined_chunk_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																				tcp_ss9006_combined_chunk_header->sim = i;
																				tcp_ss9006_combined_chunk_header->length = 2;
																				tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_chunk_header);
																				tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 0] = 0x6d;
																				tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 1] = 0x00;
																				tcp_ss9006_clients[i].xmit_length += 2;
																			}
																		} else if (tcp_ss9006_clients[i].recv_buf[j] == SIM_GSM_CLA/*0xa0*/) {
																			// select read/write command type
																			if (get_3gpp_ts_11_11_claa0_ins_type(tcp_ss9006_clients[i].recv_buf[j + 1]) < 0) {
																				// read
																				iso_iec_7816_device_command_build(&simcards[tcp_ss9006_combined_chunk_header->sim].ifacedev, &tcp_ss9006_clients[i].recv_buf[j], 0, NULL, 0);
																			} else if (get_3gpp_ts_11_11_claa0_ins_type(tcp_ss9006_clients[i].recv_buf[j + 1]) > 0) {
																				// write
																				iso_iec_7816_device_command_build(&simcards[tcp_ss9006_combined_chunk_header->sim].ifacedev, &tcp_ss9006_clients[i].recv_buf[j], CMD_WRITE, &tcp_ss9006_clients[i].recv_buf[j+5], tcp_ss9006_combined_chunk_header->length - 5);
																			} else {
																				// unknown
																				LOG("%s: Command to SIM #%03lu failed - unknown command=0x%02x from class=0x%02x\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim, tcp_ss9006_clients[i].recv_buf[j], tcp_ss9006_clients[i].recv_buf[j + 1]);
																				// prepare command response
																				tcp_ss9006_combined_header = (struct ss9006_combined_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																				tcp_ss9006_combined_header->cmd = SS9006_OPC_COMBINED;
																				tcp_ss9006_combined_header->length = sizeof(struct ss9006_combined_chunk_header) + 2;
																				tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_header);
																				tcp_ss9006_combined_chunk_header = (struct ss9006_combined_chunk_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																				tcp_ss9006_combined_chunk_header->sim = i;
																				tcp_ss9006_combined_chunk_header->length = 2;
																				tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_chunk_header);
																				tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 0] = 0x6d;
																				tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 1] = 0x00;
																				tcp_ss9006_clients[i].xmit_length += 2;
																			}
																		} else {
																			// Class not supported
																			LOG("%s: Command to SIM #%03lu failed - command class=0x%02x not supported\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim, tcp_ss9006_clients[i].recv_buf[j]);
																			// prepare command response
																			tcp_ss9006_combined_header = (struct ss9006_combined_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																			tcp_ss9006_combined_header->cmd = SS9006_OPC_COMBINED;
																			tcp_ss9006_combined_header->length = sizeof(struct ss9006_combined_chunk_header) + 2;
																			tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_header);
																			tcp_ss9006_combined_chunk_header = (struct ss9006_combined_chunk_header *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
																			tcp_ss9006_combined_chunk_header->sim = i;
																			tcp_ss9006_combined_chunk_header->length = 2;
																			tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_combined_chunk_header);
																			tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 0] = 0x6e;
																			tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length + 1] = 0x00;
																			tcp_ss9006_clients[i].xmit_length += 2;
																		}
																	} else {
																		// discard
																		LOG("%s: Command to SIM #%03lu discarded - SIM command state=%d is not idle\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim, simcards[tcp_ss9006_combined_chunk_header->sim].state);
																	}
																} else if (simcards[tcp_ss9006_combined_chunk_header->sim].client < 0) {
																	// free
																	LOG("%s: Command to SIM #%03lu failed - SIM was not binded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim);
																} else {
																	// another
																	LOG("%s: Command to SIM #%03lu failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim);
																}
															} else {
																// not inserted
																LOG("%s: Command to SIM #%03lu failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim);
															}
														} else {
															// invalid index
															LOG("%s: Command to SIM #%03lu failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_combined_chunk_header->sim, SIMBANK_SIMCARD_MAX - 1);
														}
													}
													j += tcp_ss9006_combined_chunk_header->length;
												}
												tcp_ss9006_clients[i].recv_length = 0;
												tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
											}
										}
									}
								}
								break;
							case SS9006_OPC_SIM_LED_HIDE:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										tcp_ss9006_sim_generic_request = (struct ss9006_sim_generic_request *)tcp_ss9006_clients[i].recv_buf;
										// check for valid SIM index
										if (tcp_ss9006_sim_generic_request->sim < SIMBANK_SIMCARD_MAX) {
											// check for SIM insertion status
											if (simcards[tcp_ss9006_sim_generic_request->sim].flags.inserted) {
												// check for SIM binding
												if (simcards[tcp_ss9006_sim_generic_request->sim].client == i) {
													// this - led off
#ifdef SIMBANK_LED
													sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_LED;
													sc_write_data.header.length = sizeof(sc_write_data.container.led);
													sc_write_data.container.led = 0;
													res = write(simcards[tcp_ss9006_sim_generic_request->sim].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length);
#else
													res = sizeof(sc_write_data.header) + sc_write_data.header.length;
#endif
													if (res < 0) {
														LOG("%s: SIM #%03lu LED Off failed - write(dev_fd): %s\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, strerror(errno));
													} else {
														LOG("%s: SIM #%03lu LED Off\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
													}
												} else if (simcards[tcp_ss9006_sim_generic_request->sim].client < 0) {
													// free
													LOG("%s: SIM #%03lu LED Off failed - SIM was not binded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												} else {
													// another
													LOG("%s: SIM #%03lu LED Off failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												}
											} else {
												// not inserted
												LOG("%s: SIM #%03lu LED Off failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
											}
										} else {
											// invalid index
											LOG("%s: SIM #%03lu LED Off failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, SIMBANK_SIMCARD_MAX - 1);
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_SIM_LED_SHOW:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										tcp_ss9006_sim_generic_request = (struct ss9006_sim_generic_request *)tcp_ss9006_clients[i].recv_buf;
										// check for valid SIM index
										if (tcp_ss9006_sim_generic_request->sim < SIMBANK_SIMCARD_MAX) {
											// check for SIM insertion status
											if (simcards[tcp_ss9006_sim_generic_request->sim].flags.inserted) {
												// check for SIM binding
												if (simcards[tcp_ss9006_sim_generic_request->sim].client == i) {
													// this - led on
#ifdef SIMBANK_LED
													sc_write_data.header.type = SIMCARD_CONTAINER_TYPE_LED;
													sc_write_data.header.length = sizeof(sc_write_data.container.led);
#if 0
													sc_write_data.container.led = 1;
#else
													sc_write_data.container.led = 0;
#endif
													res = write(simcards[tcp_ss9006_sim_generic_request->sim].fd, &sc_write_data, sizeof(sc_write_data.header) + sc_write_data.header.length);
#else
													res = sizeof(sc_write_data.header) + sc_write_data.header.length;
#endif
													if (res < 0) {
														LOG("%s: SIM #%03lu LED On failed - write(dev_fd): %s\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, strerror(errno));
													} else {
														LOG("%s: SIM #%03lu LED On\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
													}
												} else if (simcards[tcp_ss9006_sim_generic_request->sim].client < 0) {
													// free
													LOG("%s: SIM #%03lu LED On failed - SIM was not binded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												} else {
													// another
													LOG("%s: SIM #%03lu LED On failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												}
											} else {
												// not inserted
												LOG("%s: SIM #%03lu LED On failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
											}
										} else {
											// invalid index
											LOG("%s: SIM #%03lu LED On failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, SIMBANK_SIMCARD_MAX - 1);
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_SIM_STATUS:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										// prepare response
										tcp_ss9006_sim_status_response = (struct ss9006_sim_status_response *)&tcp_ss9006_clients[i].xmit_buf[tcp_ss9006_clients[i].xmit_length];
										tcp_ss9006_sim_status_response->hexf8 = SS9006_OPC_SIM_STATUS;
										tcp_ss9006_sim_status_response->reserved = 0;
										tcp_ss9006_clients[i].xmit_length += sizeof(struct ss9006_sim_status_response);
										// traverse SIM-crd list
										for (j = 0; j < SIMBANK_SIMCARD_MAX; j++) {
											if ((simcards[j].flags.inserted) && (!simcards[j].flags.busy) && ((simcards[j].client < 0) || (simcards[j].client == i))) {
												tcp_ss9006_sim_status_response->sim[j] = 1;
											} else {
												tcp_ss9006_sim_status_response->sim[j] = 0;
											}
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_SIM_BIND:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										tcp_ss9006_sim_generic_request = (struct ss9006_sim_generic_request *)tcp_ss9006_clients[i].recv_buf;
										// check for valid SIM index
										if (tcp_ss9006_sim_generic_request->sim < SIMBANK_SIMCARD_MAX) {
											// check for SIM insertion status
											if (simcards[tcp_ss9006_sim_generic_request->sim].flags.inserted) {
												// check for SIM binding
												if (simcards[tcp_ss9006_sim_generic_request->sim].client < 0) {
													// free
													LOG("%s: Bind SIM #%03lu succeeded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
													// set SIM owner client
													simcards[tcp_ss9006_sim_generic_request->sim].client = i;
													// notify sim state
													for (k = 0; k < ss9006_client_count; k++) {
														if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
															tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, tcp_ss9006_sim_generic_request->sim, 1, i);
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.iccid_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.iccid_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.iccid);
															}
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.spn_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.spn_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.spn);
															}
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.msisdn_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.msisdn_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.msisdn);
															}
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.imsi_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.imsi_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.imsi);
															}
														}
													}
												} else if (simcards[tcp_ss9006_sim_generic_request->sim].client == i) {
													// this client
													LOG("%s: Bind SIM #%03lu failed - SIM already binded with this client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												} else {
													// another
													LOG("%s: Bind SIM #%03lu failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												}
											} else {
												// not inserted
												LOG("%s: Bind SIM #%03lu failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
											}
										} else {
											// invalid index
											LOG("%s: Bind SIM #%03lu failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, SIMBANK_SIMCARD_MAX - 1);
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_SIM_UNBIND:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										tcp_ss9006_sim_generic_request = (struct ss9006_sim_generic_request *)tcp_ss9006_clients[i].recv_buf;
										// check for valid SIM index
										if (tcp_ss9006_sim_generic_request->sim < SIMBANK_SIMCARD_MAX) {
											// check for SIM insertion status
											if (simcards[tcp_ss9006_sim_generic_request->sim].flags.inserted) {
												// check for SIM binding
												if (simcards[tcp_ss9006_sim_generic_request->sim].client == i) {
													// this
													LOG("%s: Unbind SIM #%03lu succeeded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
													// clear SIM owner client
													simcards[tcp_ss9006_sim_generic_request->sim].client = -1;
													//
													x_timer_stop(simcards[tcp_ss9006_sim_generic_request->sim].timers.wait_time);
													//
													if (simcards[tcp_ss9006_sim_generic_request->sim].flags.iccid_req) {
														// run get iccid macro
														simcards[tcp_ss9006_sim_generic_request->sim].flags.iccid_req = 0;
														gsm_sim_cmd_get_iccid_sm(&simcards[tcp_ss9006_sim_generic_request->sim].ifacedev, 1);
														simcards[tcp_ss9006_sim_generic_request->sim].flags.iccid = 1;
														simcards[tcp_ss9006_sim_generic_request->sim].flags.busy = 1;
													} else if (simcards[tcp_ss9006_sim_generic_request->sim].flags.imsi_req) {
														// run get imsi macro
														simcards[tcp_ss9006_sim_generic_request->sim].flags.imsi_req = 0;
														gsm_sim_cmd_get_imsi_sm(&simcards[tcp_ss9006_sim_generic_request->sim].ifacedev, 1);
														simcards[tcp_ss9006_sim_generic_request->sim].flags.imsi = 1;
														simcards[tcp_ss9006_sim_generic_request->sim].flags.busy = 1;
													} else if (simcards[tcp_ss9006_sim_generic_request->sim].flags.spn_req) {
														// run get spn macro
														simcards[tcp_ss9006_sim_generic_request->sim].flags.spn_req = 0;
														gsm_sim_cmd_get_spn_sm(&simcards[tcp_ss9006_sim_generic_request->sim].ifacedev, 1);
														simcards[tcp_ss9006_sim_generic_request->sim].flags.spn = 1;
														simcards[tcp_ss9006_sim_generic_request->sim].flags.busy = 1;
													} else if (simcards[tcp_ss9006_sim_generic_request->sim].flags.msisdn_req) {
														// run get msisdn macro
														simcards[tcp_ss9006_sim_generic_request->sim].flags.msisdn_req = 0;
														gsm_sim_cmd_get_msisdn_sm(&simcards[tcp_ss9006_sim_generic_request->sim].ifacedev, 1);
														simcards[tcp_ss9006_sim_generic_request->sim].flags.msisdn = 1;
														simcards[tcp_ss9006_sim_generic_request->sim].flags.busy = 1;
													} else if (simcards[tcp_ss9006_sim_generic_request->sim].flags.erase_sms_req) {
														// run erase sms macro
														simcards[tcp_ss9006_sim_generic_request->sim].flags.erase_sms_req = 0;
														gsm_sim_cmd_erase_sms_sm(&simcards[tcp_ss9006_sim_generic_request->sim].ifacedev, 1);
														simcards[tcp_ss9006_sim_generic_request->sim].flags.erase_sms = 1;
														simcards[tcp_ss9006_sim_generic_request->sim].flags.busy = 1;
													} else {
														// start status timer
														x_timer_set_ms(simcards[tcp_ss9006_sim_generic_request->sim].timers.status, 0);
													}
													// notify sim state
													for (k = 0; k < ss9006_client_count; k++) {
														if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
															tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, tcp_ss9006_sim_generic_request->sim, 1, 0xff);
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.iccid_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.iccid_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.iccid);
															}
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.spn_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.spn_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.spn);
															}
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.msisdn_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.msisdn_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.msisdn);
															}
															if (simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.imsi_len) {
																tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.imsi_len, simcards[tcp_ss9006_sim_generic_request->sim].ifacedev.imsi);
															}
														}
													}
												} else if (simcards[tcp_ss9006_sim_generic_request->sim].client < 0) {
													// free
													LOG("%s: Unbind SIM #%03lu failed - SIM was not binded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												} else {
													// another
													LOG("%s: Unbind SIM #%03lu failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												}
											} else {
												// not inserted
												LOG("%s: Unbind SIM #%03lu failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
											}
										} else {
											// invalid index
											LOG("%s: Unbind SIM #%03lu failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, SIMBANK_SIMCARD_MAX - 1);
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_SIM_BLOCK:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										tcp_ss9006_sim_generic_request = (struct ss9006_sim_generic_request *)tcp_ss9006_clients[i].recv_buf;
										// check for valid SIM index
										if (tcp_ss9006_sim_generic_request->sim < SIMBANK_SIMCARD_MAX) {
											// check for SIM insertion status
											if (simcards[tcp_ss9006_sim_generic_request->sim].flags.inserted) {
#if 0
												// check for SIM binding
												if (simcards[tcp_ss9006_sim_generic_request->sim].client == i) {
													// this
#endif
													LOG("%s: Block SIM #%03lu succeeded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
#if 0
												} else if (simcards[tcp_ss9006_sim_generic_request->sim].client < 0) {
													// free
													LOG("%s: Block SIM #%03lu failed - SIM was not binded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												} else {
													// another
													LOG("%s: Block SIM #%03lu failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												}
#endif
											} else {
												// not inserted
												LOG("%s: Block SIM #%03lu failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
											}
										} else {
											// invalid index
											LOG("%s: Block SIM #%03lu failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, SIMBANK_SIMCARD_MAX - 1);
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_SIM_RESET:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_generic_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_generic_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_generic_request)) {
										tcp_ss9006_sim_generic_request = (struct ss9006_sim_generic_request *)tcp_ss9006_clients[i].recv_buf;
										// check for valid SIM index
										if (tcp_ss9006_sim_generic_request->sim < SIMBANK_SIMCARD_MAX) {
											// check for SIM insertion status
											if (simcards[tcp_ss9006_sim_generic_request->sim].flags.inserted) {
												// check for SIM binding
												if (simcards[tcp_ss9006_sim_generic_request->sim].client == i) {
													// this
													if (!simcards[tcp_ss9006_sim_generic_request->sim].flags.reseting) {
														LOG("%s: Reset SIM #%03lu request\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
														// set flag for reseting SIM
														simcards[tcp_ss9006_sim_generic_request->sim].flags.reset = 1;
														simcards[tcp_ss9006_sim_generic_request->sim].flags.reseting = 1;
													}
												} else if (simcards[tcp_ss9006_sim_generic_request->sim].client < 0) {
													// free
													LOG("%s: Reset SIM #%03lu failed - SIM was not binded\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												} else {
													// another
													LOG("%s: Reset SIM #%03lu failed - SIM was binded with another client\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
												}
											} else {
												// not inserted
												LOG("%s: Reset SIM #%03lu failed - SIM not inserted\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim);
											}
										} else {
											// invalid index
											LOG("%s: Reset SIM #%03lu failed - SIM index out of range=[0;%u]\n", tcp_ss9006_clients[i].prefix, (unsigned long int)tcp_ss9006_sim_generic_request->sim, SIMBANK_SIMCARD_MAX - 1);
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							case SS9006_OPC_EXTENSION:
								if (tcp_ss9006_clients[i].recv_wait < sizeof(struct ss9006_sim_extension_request)) {
									tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_sim_extension_request);
								} else {
									if (tcp_ss9006_clients[i].recv_length >= sizeof(struct ss9006_sim_extension_request)) {
										tcp_ss9006_sim_extension_request = (struct ss9006_sim_extension_request *)tcp_ss9006_clients[i].recv_buf;
										switch (tcp_ss9006_sim_extension_request->opc) {
											case SS9006_EXT_OPC_CLI_CONTROL_SET:
												tcp_ss9006_clients[i].flags.control = 1;
												tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[i], SS9006_EXT_OPC_CLI_CONTROL_SET, sim_start, sim_end, 0);
												break;
											case SS9006_EXT_OPC_CLI_INFO:
												for (j = 0; j < ss9006_client_count; j++) {
													tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[i], SS9006_EXT_OPC_CLI_INFO, j, (tcp_ss9006_clients[j].sock >= 0)?1:0, (i == j)?1:0);
													tcp_ss9006_cli_msg_ext_add_param_string(&tcp_ss9006_clients[i], 0, "%s", inet_ntoa(tcp_ss9006_clients[j].addr.sin_addr));
													tcp_ss9006_cli_msg_ext_add_param_string(&tcp_ss9006_clients[i], 1, "%u", ntohs(tcp_ss9006_clients[j].addr.sin_port));
												}
												break;
											case SS9006_EXT_OPC_SIM_INFO:
												for (j = 0; j < SIMBANK_SIMCARD_MAX; j++) {
													tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[i], SS9006_EXT_OPC_SIM_INFO, j, simcards[j].flags.inserted, ((simcards[j].client < 0)?(0xff):(simcards[j].client)));
													if ((simcards[j].flags.inserted) && (simcards[j].ifacedev.iccid_len)) {
														tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[i], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[j].ifacedev.iccid_len, simcards[j].ifacedev.iccid);
													}
													if ((simcards[j].flags.inserted) && (simcards[j].ifacedev.spn_len)) {
														tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[i], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[j].ifacedev.spn_len, simcards[j].ifacedev.spn);
													}
													if ((simcards[j].flags.inserted) && (simcards[j].ifacedev.msisdn_len)) {
														tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[i], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[j].ifacedev.msisdn_len, simcards[j].ifacedev.msisdn);
													}
													if ((simcards[j].flags.inserted) && (simcards[j].ifacedev.imsi_len)) {
														tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[i], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[j].ifacedev.imsi_len, simcards[j].ifacedev.imsi);
													}
												}
												break;
											case SS9006_EXT_OPC_KEEP_ALIVE:
												tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[i], SS9006_EXT_OPC_KEEP_ALIVE, 0, 0, 0);
												break;
											default:
												LOG("%s: Unknown SS9006_EXT_OPC=0x%02x\n", tcp_ss9006_clients[i].prefix, tcp_ss9006_sim_extension_request->opc);
												// set close flag
												tcp_ss9006_clients[i].flags.close = 1;
												break;
										}
										tcp_ss9006_clients[i].recv_length = 0;
										tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
									}
								}
								break;
							default:
								LOG("%s: Unknown SS9006_OPC=0x%02x\n", tcp_ss9006_clients[i].prefix, tcp_ss9006_base_header->opc);
								// set close flag
								tcp_ss9006_clients[i].flags.close = 1;
								break;
						}
					} else if (res < 0) {
						if (errno != EAGAIN) {
							LOG("%s: recv(tcp_ss9006_clients[i].sock) failed - %s\n", tcp_ss9006_clients[i].prefix, strerror(errno));
							// set close flag
							tcp_ss9006_clients[i].flags.close = 1;
						}
					} else {
						LOG("%s: Client \"%s:%u\" disconnected\n", tcp_ss9006_prefix, inet_ntoa(tcp_ss9006_clients[i].addr.sin_addr), ntohs(tcp_ss9006_clients[i].addr.sin_port));
						// on disconnect action
						x_timer_stop(tcp_ss9006_clients[i].timers.auth);
						x_timer_stop(tcp_ss9006_clients[i].timers.watchdog);
						close(tcp_ss9006_clients[i].sock);
						tcp_ss9006_clients[i].sock = -1;
						tcp_ss9006_clients[i].recv_length = 0;
						tcp_ss9006_clients[i].recv_wait = sizeof(struct ss9006_base_header);
						tcp_ss9006_clients[i].xmit_length = 0;
						// traverse SIM binded with this client
						for (j = 0; j < SIMBANK_SIMCARD_MAX; j++) {
							if (simcards[j].client == i) {
								// unbind SIM from this client
								simcards[j].client = -1;
								LOG("%s: Unbind SIM #%03lu succeeded\n", tcp_ss9006_clients[i].prefix, (long unsigned int)j);
								// start status timer
								x_timer_set_ms(simcards[j].timers.status, 0);
								// notify sim state
								for (k = 0; k < ss9006_client_count; k++) {
									if ((tcp_ss9006_clients[k].sock >= 0) && (tcp_ss9006_clients[k].flags.control)) {
										tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO, j, 1, 0xff);
										if (simcards[j].ifacedev.iccid_len) {
											tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_ICCID, simcards[j].ifacedev.iccid_len, simcards[j].ifacedev.iccid);
										}
										if (simcards[j].ifacedev.spn_len) {
											tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_SPN, simcards[j].ifacedev.spn_len, simcards[j].ifacedev.spn);
										}
										if (simcards[j].ifacedev.msisdn_len) {
											tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_MSISDN, simcards[j].ifacedev.msisdn_len, simcards[j].ifacedev.msisdn);
										}
										if (simcards[j].ifacedev.imsi_len) {
											tcp_ss9006_cli_msg_ext_add_param(&tcp_ss9006_clients[k], SS9006_EXT_OPC_SIM_INFO_IE_IMSI, simcards[j].ifacedev.imsi_len, simcards[j].ifacedev.imsi);
										}
									}
								}
							}
						}
						// notify client state
						for (j = 0; j < ss9006_client_count; j++) {
							if ((tcp_ss9006_clients[j].sock >= 0) && (tcp_ss9006_clients[j].flags.control)) {
								tcp_ss9006_cli_msg_ext_init(&tcp_ss9006_clients[j], SS9006_EXT_OPC_CLI_INFO, i, 0, 0);
							}
						}
					}
				}
			}
		} else if (res > 0) {
			LOG("%s: select() failed - %s\n", prefix, strerror(errno));
			goto main_end;
		}
	}

main_end:
	for (i = 0; i < ss9006_client_count; i++) {
		// close client socket
		if (tcp_ss9006_clients[i].sock > 0) {
			close(tcp_ss9006_clients[i].sock);
		}
		// free dump path
		if (tcp_ss9006_clients[i].dump) {
			free(tcp_ss9006_clients[i].dump);
		}
		// free log path
		if (tcp_ss9006_clients[i].log) {
			free(tcp_ss9006_clients[i].log);
		}
	}
	if (tcp_ss9006_clients) {
		free(tcp_ss9006_clients);
	}
	// close server socket
	close(tcp_ss9006_sock);
	for (i = 0; i < SIMBANK_SIMCARD_MAX; i++) {
		// close device file
		if (simcards[i].fd > 0) {
			close(simcards[i].fd);
		}
		// free dump path
		if (simcards[i].dump) {
			free(simcards[i].dump);
		}
		// free log path
		if (simcards[i].log) {
			free(simcards[i].log);
		}
	}
	LOG("%s: exit\n", prefix);
	// free log path
	if (log_file) {
		free(log_file);
	}
	if (daemonize) {
		unlink(pid_file);
	}
	exit(EXIT_SUCCESS);
}
