/*
udpproxy - small proxy example 

Copyright (C) 2023  Resilience Theatre

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "log.h"
#include "ini.h"
#include "binn.h"

#define MAXLINE 1000
#define MAX_MSG_SIZE 1500
#define OUTPUT_SERIALIZED 1
#define OUTPUT_PLAIN	2

void safe_fclose(FILE *fp);
long int get_key_index(char *filename);
void set_key_index(char *filename, long int index);

void update_fifo(float key_presentage)
{
	int fd;
    char *key_status_fifo = "/tmp/udpproxy-tx-key-presentage";
    mkfifo(key_status_fifo, 0666);
    char presentage_string[10];
    memset(presentage_string,0,10);
    sprintf(presentage_string,"%.2f %%",key_presentage);
	fd = open(key_status_fifo, O_WRONLY| O_NONBLOCK);
	write(fd, presentage_string, strlen(presentage_string)+1);
	close(fd);
}

void update_rx_fifo(float key_presentage)
{
	int fd;
    char *key_status_fifo = "/tmp/udpproxy-rx-key-presentage";
    mkfifo(key_status_fifo, 0666);
    char presentage_string[10];
    memset(presentage_string,0,10);
    sprintf(presentage_string,"%.2f %%",key_presentage);
	fd = open(key_status_fifo, O_WRONLY| O_NONBLOCK);
	write(fd, presentage_string, strlen(presentage_string)+1);
	close(fd);
}

void safe_fclose(FILE *fp)
{
	if (fp && fp != stdout && fp != stderr) {
		if (fclose(fp) == EOF) {
			perror("fclose()");
		}
		fp = NULL;
	}
}

long int get_file_size (char *filename) {
	struct stat st;
	long int size=0;
	stat(filename, &st);
	size = st.st_size;
	return size;
}

long int get_key_index(char *filename) {
	long int index=0;
	FILE *keyindex_file;
	keyindex_file = fopen(filename, "rb");
	fread(&index, sizeof(long int),1,keyindex_file);
	safe_fclose(keyindex_file);
	return index;
}

void set_key_index(char *filename, long int index) {
	FILE *keyindex_file;
	keyindex_file = fopen(filename, "wb");
	fwrite(&index, sizeof(long int), 1, keyindex_file);
	safe_fclose(keyindex_file);
}

void getkey(char *filename, char* keybuf, long int start_index, int len, bool overwrite)
{	
	FILE *keyfile;
	size_t freadlen=0;
	keyfile = fopen(filename, "rb");
	if (fseek(keyfile, start_index, SEEK_SET)) {
			printf("Seek error!\n");
	}
	freadlen = fread(keybuf, sizeof(char),len,keyfile);
	if ( freadlen == 0 ) {
		log_error("[%d] %s fread return: %d ", getpid(),filename,freadlen);	
		log_error("[%d] You run out of key material! Exiting. ", getpid());	
		exit(0);
	}
	safe_fclose(keyfile);
	if ( overwrite == TRUE )
	{
		log_debug("[%d] Key %s overwrite at: %ld len: %d", getpid(),filename,start_index,len);
		char *zerobuf = malloc(len);
		memset(zerobuf,0xFF,len);
		int f_read = open(filename, O_WRONLY);
		lseek (f_read, start_index, SEEK_CUR);
		write(f_read, zerobuf, len);
		close(f_read);
		free(zerobuf);
		log_debug("[%d] Key overwrite complete and buffers free'd", getpid() );
	}
}

void print_hex_memory(void *mem, int buflen) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<buflen;i++) {
    printf("0x%02x ", p[i]);
    if ((i%16==0) && i)
      printf("\n");
  }
  printf("\n");
}

int encryptpacket(char *buf, unsigned int buflen, char *serializedbuf, char *keyfile,char* outbound_counter_file)
{	
	static long int tx_key_ref;
	int packet_size;
	unsigned char *xorbytes = malloc(buflen);
	memset(xorbytes, 0, buflen);
	char *key = malloc(buflen);
	memset(key, 0, buflen);
	long int tx_key_used = get_key_index(outbound_counter_file);
	
		getkey(keyfile,key,tx_key_used-buflen,buflen,TRUE);
		for(int i = 0; i < buflen; ++i)
		{
			xorbytes[i] = buf[i] ^ key[i];
		}

	tx_key_used = tx_key_used + buflen;
	set_key_index(outbound_counter_file, tx_key_used);
		
		binn *obj;
		obj = binn_object();
		binn_object_set_blob(obj, "packet", xorbytes,buflen);
		binn_object_set_int64(obj, "keyindex", tx_key_used-buflen);
		binn_object_set_int32(obj, "buflen", buflen);	
		memcpy(serializedbuf,binn_ptr(obj), binn_size(obj));
		packet_size = binn_size(obj);
		binn_free(obj);
		free(xorbytes);
		
		if (tx_key_used > tx_key_ref ) {
			long int key_file_size = get_file_size(keyfile);
			float key_presentage = (100.0*tx_key_used)/key_file_size;
			tx_key_ref = tx_key_used + 10000;
			log_info("[%d] TX key used: %ld (of %ld) %.2f %%",getpid(),tx_key_used,key_file_size,key_presentage );
			update_fifo(key_presentage);
		}
	 return packet_size;
}

int decryptpacket(char *buf,char *rxbuffer,int readbytes,char* keyfile, char* inbound_counter_file)
{	
	static long int rx_key_ref;
	unsigned char *serializedbuf; 
	long int keyindex;
	int buflen;
	char *key;
	binn *obj;
    if ( readbytes < 4 ) 
    {
        log_error("[%d] de-serialization sanity check detected shorted than 4 bytes packet, discarding.",getpid());
        return 0;
    }
    if (binn_is_valid_ex(rxbuffer, NULL, NULL, &readbytes) == FALSE) 
    {
        log_error("[%d] de-serialization sanity check detected non valid packet, discarding.",getpid());
        return 0;
    }
	obj = binn_open(rxbuffer);
	keyindex = binn_object_int64(obj, "keyindex");
	buflen = binn_object_int32(obj, "buflen");
	serializedbuf = binn_object_blob(obj, "packet",&buflen);
	binn_free(obj);
	key = malloc(buflen);
	memset(key, 0, buflen);
	getkey(keyfile,key,keyindex-buflen,buflen,TRUE);	
	for(int i = 0; i < buflen; ++i)
	{
		buf[i] = serializedbuf[i] ^ key[i];
	}
	set_key_index(inbound_counter_file, keyindex + buflen );
	long int rx_key_used = keyindex + buflen;
	if (rx_key_used > rx_key_ref ) {	
		long int key_file_size = get_file_size(keyfile);
		float key_presentage = (100.0*rx_key_used)/key_file_size;
		rx_key_ref = rx_key_used + 10000;
		log_info("[%d] RX key used: %ld (of %ld) %.2f %%",getpid(),rx_key_used,key_file_size,key_presentage );
		update_rx_fifo(key_presentage);
	}
	return buflen;
}



int main(int argc, char *argv[])
{
	char *incoming_address=NULL;
	char *incoming_port=NULL;
	char *outgoing_address=NULL;
	char *outgoing_port=NULL;
	char *outbound_key = NULL;
	char *inbound_key = NULL;
	char *outbound_counter = NULL;
	char *inbound_counter = NULL;
	char *ini_file=NULL;
	int log_level=LOG_INFO;
	int c=0;
	
	/* ini-file */
	while ((c = getopt (argc, argv, "dhi:")) != -1)
	switch (c)
	{
		case 'd':
			log_level=LOG_DEBUG;
			break;
		case 'i':
			ini_file = optarg;
			break;
		case 'h':
			log_info("[%d] udpproxy",getpid());
			log_info("[%d] Usage: -i [ini_file] ",getpid());
			log_info("[%d]        -d debug log ",getpid());
			return 1;
		break;
			default:
			break;
	}
	if (ini_file == NULL) 
	{
		log_error("[%d] ini file not specified, exiting.", getpid());
		return 0;
	}
	log_set_level(log_level);
	
	ini_t *config = ini_load(ini_file);
	if (config == NULL ) {
		log_error("[%d] Cannot open ini-file, exiting.", getpid());
		return 0;
	}
	ini_sget(config, "proxy", "incoming_address", NULL, &incoming_address);
	ini_sget(config, "proxy", "incoming_port", NULL, &incoming_port);
	ini_sget(config, "proxy", "outgoing_address", NULL, &outgoing_address);
	ini_sget(config, "proxy", "outgoing_port", NULL, &outgoing_port);
	ini_sget(config, "proxy", "outbound_key", NULL, &outbound_key);
	ini_sget(config, "proxy", "inbound_key", NULL, &inbound_key);
	ini_sget(config, "proxy", "outbound_counter_file", NULL, &outbound_counter);
	ini_sget(config, "proxy", "inbound_counter_file", NULL, &inbound_counter);
	
	log_info("[%d] Incoming address: %s Port: %s ",getpid(),incoming_address,incoming_port);
	log_info("[%d] Outgoing address: %s Port: %s ",getpid(),outgoing_address,outgoing_port);
	
	// Test key access
	if( access( outbound_key, W_OK ) == 0 ) {
		log_info("[%d] Outbound key file: %s",getpid(),outbound_key);
	} else {
		log_error("[%d] Cannot open outbound key file: %s. Need a writable file.",getpid(),outbound_key);
	}
	if( access( inbound_key, W_OK ) == 0 ) {
		log_info("[%d] Inbound key file: %s",getpid(),inbound_key);
	} else {
		log_error("[%d] Cannot open inbound key file: %s. Need a writable file.",getpid(),inbound_key);
	}
	if( access( outbound_counter, W_OK ) == 0 ) {
		log_info("[%d] Outbound key counter file: %s",getpid(),outbound_counter);
	} else {
		log_error("[%d] Cannot open outbound key counter file: %s. Need a writable file.",getpid(),outbound_counter);
	}
	if( access( inbound_counter, W_OK ) == 0 ) {
		log_info("[%d] Inbound key counter file: %s",getpid(),inbound_counter);
	} else {
		log_error("[%d] Cannot open inbound key counter file: %s. Need a writable file.",getpid(),inbound_counter);
	}
	
	// Incoming socket
	int incoming_fd;
	unsigned int len;
	char buffer[MAX_MSG_SIZE];
	struct sockaddr_in servaddr_in, cliaddr;
	bzero(&servaddr_in, sizeof(servaddr_in));
	
	// Outgoing socket 
	int outgoing_fd;
	struct sockaddr_in servaddr_out;
	bzero(&servaddr_out, sizeof(servaddr_out));

	// Incoming: create socket & bind it 
	incoming_fd = socket(AF_INET, SOCK_DGRAM, 0);		
	servaddr_in.sin_addr.s_addr = inet_addr(incoming_address);
	servaddr_in.sin_port = htons(atoi(incoming_port));
	servaddr_in.sin_family = AF_INET;
	bind(incoming_fd, (struct sockaddr*)&servaddr_in, sizeof(servaddr_in));
	
	// Outgoing: prepare address & connect socket
	servaddr_out.sin_addr.s_addr = inet_addr(outgoing_address);
	servaddr_out.sin_port = htons(atoi(outgoing_port));
	servaddr_out.sin_family = AF_INET;	
	outgoing_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(connect(outgoing_fd, (struct sockaddr *)&servaddr_out, sizeof(servaddr_out)) < 0)
	{
		log_error("[%d] outgoing connection failed, exiting.",getpid());
		exit(0);
	}
	
	while ( 1 ) {

		// Plain data in -> Serialize Out
		// Serialized data in -> Plain data out				
		int output_mode=0;
		// Incoming: receive data
		len = sizeof(cliaddr);
		bzero(buffer,sizeof(buffer));
		int n = recvfrom(incoming_fd, buffer, sizeof(buffer),
				0, (struct sockaddr*)&cliaddr,&len); 
		buffer[n] = '\0';

		/* Evaluate serialization */
		binn *in_obj;
		in_obj = binn_open(buffer);		
		if (in_obj == NULL) {
			// plain data in -> serialize and send serialized
			output_mode = OUTPUT_SERIALIZED;
		} else {
			output_mode = OUTPUT_PLAIN;
		}
		
		// output plain data from serialized input
		if ( output_mode == OUTPUT_PLAIN ) {
			
			// de-serialize, then output plain
			char *rxbuffer = malloc(n);
			memset(rxbuffer, 0, n);
			int decryptedbytes = decryptpacket(rxbuffer,buffer,n,inbound_key,inbound_counter);
			sendto(outgoing_fd, rxbuffer, decryptedbytes, 0, (struct sockaddr*)NULL, sizeof(servaddr_out));
			log_debug("[%d] Plain data sent to %s %s",getpid(),outgoing_address,outgoing_port);
			free (rxbuffer);			
		}

		// serialize and then output serialized data: 
		if ( output_mode == OUTPUT_SERIALIZED ) {
			char serializedbuf[2000]; 
			memset(serializedbuf, 0, 2000);
			int serialized_packet_len = encryptpacket(buffer,n,serializedbuf,outbound_key, outbound_counter);
			if( sendto( outgoing_fd, serializedbuf, serialized_packet_len, 0, (struct sockaddr*)NULL, sizeof(servaddr_out) ) == -1) {
				perror("sendto");
				exit(1);
			}			
			log_debug("[%d] Serialized data sent to %s %s",getpid(),outgoing_address,outgoing_port);
		}
	}
	// outgoing: close socket
	close(outgoing_fd);
	return 0;
}




