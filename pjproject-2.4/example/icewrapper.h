#ifndef _ICE_WRAPPER_H_
#define _ICE_WRAPPER_H_


#include <stdio.h>
#include <stdlib.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <getopt.h>

//#include "pjnath/stun_config.h"
//#include "pjnath/ice_session.h"
//#include "pjnath/ice_strans.h"
#include "pj/types.h"

#define THIS_FILE   "icewrapper.c"

/* For this demo app, configure longer STUN keep-alive time
 * so that it does't clutter the screen output.
 */
#define KA_INTERVAL 300


/* Command line options are stored here */
typedef struct ice_option_s
{
    unsigned    comp_cnt;
    pj_str_t    ns;
    int	    max_host;
    pj_bool_t   regular;
    pj_str_t    stun_srv;
    pj_str_t    turn_srv;
    pj_bool_t   turn_tcp;
    pj_str_t    turn_username;
    pj_str_t    turn_password;
    pj_bool_t   turn_fingerprint;


    // option for signalling-server 
    
    char gUserID[256];
    char gCloudSrvAdd[256];
    int gCloudSrvAddPort;

} ice_option_t;




typedef void (*callback_rx_data_f)(pj_ice_strans *, unsigned, void *, pj_size_t,
                          const pj_sockaddr_t *,
                          unsigned );



typedef void (*callback_ice_complete_f)(pj_ice_strans *,
                               pj_ice_strans_op ,
                               pj_status_t );


typedef struct v_ice_trans_s{

    char name[256];
    enum {
        ICE_TRAN_STATE_NO = 0,
        ICE_TRAN_STATE_CONNECTED,
    }state;


    /* Our global variables */
    pj_caching_pool	 cp;
    pj_pool_t		*pool;
    pj_thread_t		*thread;
    pj_bool_t		 thread_quit_flag;

    pj_ice_strans_cfg	 ice_cfg;
    pj_ice_strans	*icest;

    // TODO: should be an array so that it can support each ICE trans
    struct rem_info
    {
        char		 ufrag[80];
        char		 pwd[80];
        unsigned	 comp_cnt;
        pj_sockaddr	 def_addr[PJ_ICE_MAX_COMP];
        unsigned	 cand_cnt;
        pj_ice_sess_cand cand[PJ_ICE_ST_MAX_CAND];
    } rem;

    FILE		*log_fhnd;

    callback_rx_data_f cb_on_rx_data;
    callback_ice_complete_f cb_on_ice_complete;

} v_ice_trans_t;



pj_status_t icedemo_init(v_ice_trans_t *icetrans, ice_option_t opt);
void err_exit( const char *title, pj_status_t status , struct v_ice_trans_s* icetrans);

void icedemo_create_instance(struct v_ice_trans_s* icetrans, ice_option_t opt);
void reset_rem_info(struct v_ice_trans_s* icetrans);
void get_and_register_SDP_to_cloud(struct v_ice_trans_s* icetrans, ice_option_t opt, char *usrid);
void vnat_stun_detect_nat_type(v_ice_trans_t  *ice_tran, pj_str_t stun_srv);




#endif
