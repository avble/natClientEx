#ifndef _ICE_SESSION_MANAGER_
#define  _ICE_SESSION_MANAGER_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <pthread.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>



typedef struct ICESession_s
{
    struct ICESession_s *psNext;
    pj_ice_strans *ice_trans_name;

    unsigned int comp_id;

    pj_sockaddr_t *src_addr;
    unsigned int src_addr_len;

    // just wonder if it is need 
    char device_name[256];
    // FIXME: ICE tran should be here 

} ICESession_t;




typedef struct ICESessionList_s{
    ICESession_t *ice_session_list;    
 
    pthread_mutex_t     Lock;
}ICESessionList_t; 


// initialize the rule 
void ice_session_init();
// add a rule to list 
void ice_session_add(ICESession_t *rule);

void ice_session_add_ice_trans(pj_ice_strans *ice_trans_name, const unsigned int  comp_id, const pj_sockaddr_t *src_addr, unsigned int src_addr_len);

// remove a rule from list 
void ice_session_remove(char *rule_name);
void ice_session_quit();

void ice_session_notify_all();

void ice_session_print();



#endif
