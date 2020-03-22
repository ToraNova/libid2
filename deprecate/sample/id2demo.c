/*
 * ID2 demo is a demonstration use of the id2 library
 * This demo runs a tight BLS IBI verifier server
 * written by ToraNova: chia_jason96@live.com
 *

The MIT License (MIT)

Copyright (c) 2019 Chia Jason

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 * compile:
 * gcc -lid2 <filename>
 */

#include "id2.h"

#include <time.h>
#include <argp.h>
#include <stdlib.h>

//DEFAULT VALUES

//PARAM FILE LIST
//#define str_paramfile 	"params/d192.param" // 0.2635ms; 0.02136ms; 0.2695ms
//#define str_paramfile 	"params/d256.param" // 0.3529ms; 0.03157ms; 0.3502ms
#define str_paramfile 	"params/d359.param" // 0.7103ms; 0.05930ms; 0.7185ms
//#define str_paramfile 	"params/d407.param" // 0.8678ms; 0.08130ms; 0.9269ms
//#define str_paramfile 	"params/d522.param" // 1.522ms; 0.1323ms; 1.653ms
//#define str_paramfile 	"params/d677.param" // 2.440ms; 0.2242ms; 2.717ms
//#define str_paramfile 	"params/d1357.param" // 12.273ms; 0.9747ms; 14.91ms

#define str_publicfile 	"res/vblsibi/public"
#define str_secretfile 	"res/vblsibi/secret"
#define str_idfile 	"res/vblsibi/id"
#define str_uskfile 	"res/vblsibi/usk"

#define str_host 	"127.0.0.1"

/*
 * Argparser (Commandline ftw)
 */
const char *argp_program_version = "vbls_id2 simple verifier v1.0";
const char *argp_program_bug_address = "chia_jason96@live.com";
static char doc[] = "VBLS IBI scheme using id2 library - A simple verifier program.\nMode: (Setup/Ext/Prove/Verify)";
static char args_doc[] = "Mode"; //mode to specify
static struct argp_option options[] = {
	{ "paramfile", 'a', "<param>", 0, "Parameter File for pairing setup (In)"},
	{ "publicfile", 'x', "<pub>", 0, "Public Key File for Setup/Ext/Verify (Out/In/In)"},
	{ "secretfile", 's', "<sec>", 0, "Secret Key File for Setup/Ext (Out/In)"},
	{ "uidfile", 'i', "<uid>", 0, "User ID File for Ext (In)"},
	{ "uskfile", 'u', "<usk>", 0, "User Secret Key File for Ext/Prove (Out/In)"},
	{ "port", 'p', "<port>", 0, "Port to connect/listen on (Prove/Verify). Default 8051"},
	{ "host", 't', "<host>", 0, "Host to connect on (Verify). Default \'127.0.0.1\'"},
	{ "persist", 'e', NULL, 0, "Whether the verifier server should persist (loop). Default for one-shot"},
	{ 0 }
};


//editable
struct arguments {
	char *strpar;
	char *strpub;
	char *strsec;
	char *strusk;
	char *strid;
	int port;
	char *ipaddr;
	int persist;
	enum { SETUP, EXTRACT, PROVE, VERIFY } id2mode; //for multi type classes
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	char *end;
	switch (key) {
		case 'e': arguments->persist = 1; break;
		case 'a': arguments->strpar = arg; break;
		case 'x': arguments->strpub = arg; break;
		case 's': arguments->strsec = arg; break;
		case 'i': arguments->strid = arg; break;
		case 'u': arguments->strusk = arg; break;
		case 't': arguments->ipaddr = arg; break;
		case 'p': arguments->port = strtol( arg, &end, 10); //parse to base10
			if( errno == ERANGE ){
				//error handling
				printf("Range_Error on port, falling back to 8051\n");
				errno = 0;
				arguments->port = 8051; //fallback value
			} break;

		case ARGP_KEY_ARG:
			if( strcmp( arg, "setup") == 0 ){
				arguments->id2mode = SETUP; break;
			}else if( strcmp( arg,"ext") == 0 ){
				arguments->id2mode = EXTRACT; break;
			}else if( strcmp( arg,"prove") == 0 ){
				arguments->id2mode = PROVE; break;
			}else if( strcmp( arg,"verify") == 0 ){
				arguments->id2mode = VERIFY; break;
			}else{
				argp_usage( state ); break;
			}

		case ARGP_KEY_END:
			if( state->arg_num < 1 ){
				/* not enough arguments */
				argp_usage( state ); break;
			}
			break;
		default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
static char defpar[] = str_paramfile;
static char defsec[] = str_secretfile;
static char defpub[] = str_publicfile;
static char defid[] = str_idfile;
static char defusk[] = str_uskfile;
static char defhost[] = str_host;

int main(int argc, char *argv[]){

	struct arguments arguments;
	int rc;
	unsigned char *pbuf, *sbuf, *obuf, *mbuf;
	size_t plen, slen, mlen, olen;

	// default argument values
	arguments.persist = 0; //oneshot default
	arguments.port = 8051;
	arguments.ipaddr = defhost;
	arguments.strpar = defpar;
	arguments.strpub = defpub;
	arguments.strsec = defsec;
	arguments.strid  = defid;
	arguments.strusk = defusk;

	// perform parsing, result in var 'arguments'
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	// read curve params
	FILE *paramfile = fopen( arguments.strpar, "r");
	FILE *publicfile, *secretfile;
	FILE *idfile, *uskfile;
	char param[PARAM_BUF_SZ];
	size_t count = fread(param, 1, PARAM_BUF_SZ, paramfile);
	log_info("Reading params from %s", arguments.strpar);

	// main program
	switch ( arguments.id2mode ){
		case SETUP:
			// SETUP. opens public and secret file, writes the key and exit
			// THIS IS ESSENTIALLY KEYGEN FOR THE ENTIRE SYSTEM
			publicfile = fopen( arguments.strpub, "w");
			secretfile = fopen( arguments.strsec, "w");

			vbls_ibi_setup( param, count, &pbuf, &plen, &sbuf, &slen);

			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			log_info("Setup: Writing from file public:%s", arguments.strpub);
			log_info("Setup: Writing from file secret:%s", arguments.strsec);

			fclose(publicfile);
			fclose(secretfile);
			free(pbuf);
			free(sbuf);
			break;
		case EXTRACT:
			// EXTRACT. extract user secret key from their ID using public and secret
			// THIS allows the user to use their usk to verify in the future
			publicfile = fopen( arguments.strpub, "r");
			secretfile = fopen( arguments.strsec, "r");
			idfile = fopen( arguments.strid, "r");
			uskfile = fopen( arguments.strusk, "w");

			log_info("Extract: Reading from file public:%s", arguments.strpub);
			log_info("Extract: Reading from file secret:%s", arguments.strsec);
			log_info("Extract: Reading from file id:%s", arguments.strid);

			pbuf = read_b64( publicfile, &plen );
			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( idfile, &mlen );

			vbls_ibi_extract( param, count, pbuf, plen, sbuf, slen, mbuf, mlen, &obuf, &olen);

			log_info("Extract: Writing to file usk:%s", arguments.strusk);

			write_b64( uskfile, obuf, olen );

			fclose(publicfile);
			fclose(secretfile);
			fclose(idfile);
			fclose(uskfile);

			free(pbuf);
			free(sbuf);
			free(mbuf);
			free(obuf);
			break;

		case PROVE:
			// PROVE, initiate the PROVE protocol with a known verifier
			//publicfile = fopen( arguments.strpub, "r");
			idfile = fopen( arguments.strid, "r");
			uskfile = fopen( arguments.strusk, "r");

			log_info("Prove: Reading from file usk:%s", arguments.strusk);
			log_info("Prove: Reading from file id:%s", arguments.strid);

			//pbuf = read_b64( publicfile, &plen );
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			rc = vbls_ibi_prove( param, count,
					NULL, 0, mbuf, mlen, obuf, olen,
					arguments.port, arguments.ipaddr, 10);
			if(rc==0){
				log_info("prove success");
			}else{
				log_info("prove fail");
			}
			//fclose(publicfile);
			fclose(idfile);
			fclose(uskfile);
			//free(pbuf);
			free(obuf);
			free(mbuf);
			break;

		case VERIFY:
			// VERIFY, initiate the VERIFY protocol on a port
			publicfile = fopen( arguments.strpub, "r");
			pbuf = read_b64( publicfile, &plen );
			log_info("Verify: Reading from file public:%s", arguments.strpub);

			do{
				rc = vbls_ibi_verify( param, count, pbuf, plen, &mbuf, &mlen, arguments.port, 10);
				if(rc==0){
					log_info("Verify: Success 0x00 [%s]", mbuf);
				}else{
					log_info("Verify: Fail 0x01 [%s]", mbuf);
				}

			}while(arguments.persist);

			fclose(publicfile);
			free(pbuf);

			break;

		default:
			log_err("Invalid mode %d", arguments.id2mode);
			break;

	}
	fclose(paramfile);
	return 0;
}
