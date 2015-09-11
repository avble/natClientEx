#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iceSessionManager.h"

static ICESessionList_t *gIceSessionList = NULL;



// initialize ice session 
void ice_session_init()
{
   if (gIceSessionList != NULL)
        return;

    
    gIceSessionList = (ICESessionList_t *)calloc(1, sizeof(ICESessionList_t));
  
}

// Insert at the head of list  
void ice_session_add(ICESession_t *ice_session)
{
//    printf("%s %d \n", __func__, __LINE__);
    pthread_mutex_lock(&gIceSessionList->Lock);

//    printf("%s %d \n", __func__, __LINE__);

    
    if (gIceSessionList->ice_session_list == NULL)
    {
        gIceSessionList->ice_session_list = ice_session;
        gIceSessionList->ice_session_list->psNext =NULL;
    }
    else
    {
        ice_session->psNext = gIceSessionList->ice_session_list;
        gIceSessionList->ice_session_list = ice_session;
    }
    pthread_mutex_unlock(&gIceSessionList->Lock);
    
}



// remove a ice session from list 
void ice_session_remove(char *device_name)
{
    ICESession_t *tmp, *prev;
    tmp = gIceSessionList->ice_session_list;
    pthread_mutex_lock(&gIceSessionList->Lock);
    
    while(tmp != NULL)
    {
        if(strcmp(tmp->device_name, device_name) == 0)
        {
        //printf("[DEBUG] %s %d ice session name: %s \n", __func__, __LINE__, device_name);
            if(tmp == gIceSessionList->ice_session_list)
            {
            //printf("[DEBUG] %s %d ice session name: %s \n", __func__, __LINE__, device_name);
                gIceSessionList->ice_session_list = tmp->psNext;
                free(tmp);
                break;
            }
            else
            {
            //printf("[DEBUG] %s %d ice session name: %s \n", __func__, __LINE__, device_name);
                prev->psNext=tmp->psNext;
                free(tmp);
                break ;
            }
        }
        else
        {
        //printf("[DEBUG] %s %d ice session name: %s \n", __func__, __LINE__, device_name);
            prev=tmp;
            tmp= tmp->psNext;
        }
    }

    pthread_mutex_unlock(&gIceSessionList->Lock);
    return;
}

static bool ice_session_exist(pj_ice_strans *ice_trans_name)
{
    ICESession_t *tmp, *prev;
    tmp = gIceSessionList->ice_session_list;
    bool is_exist = false;
    pthread_mutex_lock(&gIceSessionList->Lock);

    printf("[DEBUG] %s %d ice session name: %X \n", __func__, __LINE__, ice_trans_name);
    while(tmp != NULL)
    {
        printf("[DEBUG] %s %d ice session name: %X \n", __func__, __LINE__, tmp->ice_trans_name);
        if(tmp->ice_trans_name == ice_trans_name)
        {
            is_exist = true;
            break;
        }
        else
        {
        //printf("[DEBUG] %s %d ice session name: %s \n", __func__, __LINE__, device_name);
            prev=tmp;
            tmp= tmp->psNext;
        }
    }

    pthread_mutex_unlock(&gIceSessionList->Lock);

    return is_exist;
    
}

static bool binary_cmp(char *s1, char *s2, int len)
{
    bool is_equal = true;

    int index = 0;

    while (index < len)
    {
        if (*(s1 + index) != *(s2 + index))
        {
            is_equal = false;
            break;
        }
        index++;
    }

    return is_equal;

}

static bool ice_src_addr_exist(const pj_sockaddr_t *src_addr, unsigned int src_addr_len)
{
    ICESession_t *tmp, *prev;
    tmp = gIceSessionList->ice_session_list;
    bool is_exist = false;
    pthread_mutex_lock(&gIceSessionList->Lock);

    //printf("[DEBUG] %s %d ice session name: %X \n", __func__, __LINE__, ice_trans_name);
    while(tmp != NULL)
    {
        printf("[DEBUG] %s %d ice session name: %X \n", __func__, __LINE__, tmp->ice_trans_name);
        if(binary_cmp(src_addr, tmp->src_addr, src_addr_len) == true)
        {
            is_exist = true;
            break;
        }
        else
        {
        //printf("[DEBUG] %s %d ice session name: %s \n", __func__, __LINE__, device_name);
            prev=tmp;
            tmp= tmp->psNext;
        }
    }

    pthread_mutex_unlock(&gIceSessionList->Lock);

    return is_exist;
    
}



void ice_session_add_ice_trans(pj_ice_strans *ice_trans_name, const unsigned int  comp_id, const pj_sockaddr_t *src_addr, unsigned int src_addr_len)
{
    printf("[DEBUG] %s %d \n", __func__, __LINE__);

    if (ice_src_addr_exist(src_addr, src_addr_len) == true)
    {
        printf("[DEBUG] %s %d ice session name: %X \n", __func__, __LINE__, ice_trans_name);
        return;
    }
    printf("[DEBUG] %s %d \n", __func__, __LINE__);

    ICESession_t *ice_session_trans = (ICESession_t *)calloc(1, sizeof(ICESession_t));
    ice_session_trans->ice_trans_name = ice_trans_name;
    ice_session_trans->comp_id = comp_id;
    ice_session_trans->src_addr_len = src_addr_len; 
    ice_session_trans->src_addr = calloc(1, src_addr_len);
    memcpy(ice_session_trans->src_addr, src_addr, src_addr_len);
    printf("[DEBUG] %s %d \n", __func__, __LINE__);

    ice_session_add(ice_session_trans);
    printf("[DEBUG] %s %d \n", __func__, __LINE__);

}


void ice_session_quit()
{
    if (gIceSessionList == NULL)
        return;

    pthread_mutex_destroy(&gIceSessionList->Lock);


    ICESession_t *ice_session = gIceSessionList->ice_session_list;
    
    while (ice_session != NULL)
    {
        gIceSessionList->ice_session_list = gIceSessionList->ice_session_list->psNext;
        free(ice_session);
        ice_session = gIceSessionList->ice_session_list;
    }

    free(gIceSessionList);
    gIceSessionList = NULL;

}

void ice_session_notify_all()
{

    printf("[DEBUG] %s %d \n", __func__, __LINE__);

    char data_tmp[2048]; 
    strcpy(data_tmp, "hello from abcd");

   ICESession_t *cur;
    cur = gIceSessionList->ice_session_list;
    bool is_exist = false;
    pthread_mutex_lock(&gIceSessionList->Lock);
    
    while(cur != NULL)
    {
        printf("[DEBUG] %s %d \n", __func__, __LINE__);
        pj_ice_strans_sendto(cur->ice_trans_name, cur->comp_id, data_tmp, strlen(data_tmp),
                                      cur->src_addr,
                                      cur->src_addr_len);
        cur = cur->psNext;
    }

    printf("[DEBUG] %s %d \n", __func__, __LINE__);

    pthread_mutex_unlock(&gIceSessionList->Lock);
    
}




