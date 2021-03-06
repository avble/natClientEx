#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include "icewrapper.h"

void read_config(char path[], ice_option_t *opt)
{
    FILE *file = fopen(path, "r");
    if (file == NULL)
        return; 


    while (!feof(file))
    {
        char key[256];
        char value[256];
        char line[256];

        bzero(key, sizeof(key));
        bzero(value, sizeof(value));
        bzero(line, sizeof(line));

        if (fgets(line, sizeof(line), file) == NULL)
            continue; 

        if (line[0] == '#' || line[0] == ' ' || line[0] == 10)
            continue; 

        sscanf(line,  "%s %s", key, value);

        if (strcmp(key, "signalling") == 0)
        {
            strcpy(opt->gCloudSrvAdd, value);
        }
        else if (strcmp(key, "signalling-port") == 0)
        {
            opt->gCloudSrvAddPort = atoi(value);
        }/*
        else if (strcmp(key, "signalling-port") == 0)
        {
            strcpy(nat_client->g, value);
        } */
        printf("[Debug] key: %s, value: %s \n",  key, value);
        
    } 
    fclose(file);
}


#if __TEST__

int main(int argc, char *argv[])
{
    read_config("config");
}

#endif
