#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <malloc.h>
#include <pwd.h>
#include <time.h>


#include <security/pam_appl.h>
#include <security/pam_modules.h>





#define MAX_COUNT 3
#define DEFAULT_LOGFILE "/var/log/faillog"

#define DEFAULT_GROUPFILE "/etc/group"
#define STR_ADMIN "astra-admin"

#define DEFAULT_USERSFILE "/etc/passwd"

/*Структура файла faillog*/
struct	faillog {
	short	fail_cnt;	/* failures since last success */
	short	fail_max;	/* failures before turning account off */
	char	fail_line[12];	/* last failure occured here */
	time_t	fail_time;	/* last failure occured then */
	/*
	 * If nonzero, the account will be re-enabled if there are no
	 * failures for fail_locktime seconds since last failure.
	 */
	long	fail_locktime;
};


int user_is_admin(pam_handle_t *pamh, const char **user)
{
    FILE *group;
    
    char *line=NULL;
    size_t c =  0;
    size_t read;
    int len = strlen(STR_ADMIN)+1;
    char *buf = (char*)malloc(sizeof(char) * len);
    
    if(!(group = fopen(DEFAULT_GROUPFILE,"r")))
    {
        pam_syslog(pamh, LOG_ALERT, "Error opening %s for %s", DEFAULT_GROUPFILE, "read");
        return 0;
    }
    
    while (fgets(buf, len, group)) {
        if(strcmp(buf,STR_ADMIN)==0)
        {
            read = getline(&line, &c, group);
            break;
        }
    }
    
    fclose(group);
    
    if(line == NULL)
        return 0;
    
    int i ;
    int s = 8;
    int f;
    
    for( i = 8; i < read ;++i)
    {
        if(line[i]==',' || line[i]=='\n')
        {
            f = i;
            int k;
            if((k = strncmp(&line[s], *user, f-s)) == 0)
                return 1;
            else
                s = f + 1;
        }
    }
    
    return 0;
}

int get_users(pam_handle_t *pamh, char ***users, uid_t **uids, int *size)
{
    int capacity = 10;
    
    *users = (char**)malloc(sizeof(char*)*capacity);
    *uids = (uid_t*)malloc(sizeof(uid_t)*capacity);
    *size = 0;
    
    
    FILE * fusers;
    
    char *line=NULL;
    size_t capacity_line =  0;
    size_t size_line;

    char *sep=":";
    char *uid;
    char *name;
    int number;
    
   if((fusers =fopen(DEFAULT_USERSFILE, "r")) == NULL)
    {
        pam_syslog(pamh, LOG_ALERT, "Error opening %s for %s", DEFAULT_USERSFILE, "read");
        return PAM_AUTH_ERR;
    }
    
    while((size_line = getline(&line, &capacity_line, fusers))!= -1)
    {
        name = strtok(line, sep);
        strtok(NULL, sep);
        uid = strtok(NULL, sep);
        number = atoi(uid);
        if(number >= 1000 && number != 65534)
            {
                (*users)[*size] = (char*)malloc(sizeof(char)*strlen(name));
                strcpy((*users)[*size], name);
                (*uids)[*size] = number;
                (*size)++;
                if(*size == capacity)
                {
                    char **buf_users = *users;
                    uid_t *buf_uids = *uids;
                    *users = (char**)malloc(sizeof(char*)*(capacity+10));
                    *uids = (uid_t*)malloc(sizeof(uid_t)*(capacity+10));
                    
                    int i;
                    for(i = 0; i < capacity;++i)
                    {
                        (*users)[i] = (char*)malloc(sizeof(char)*strlen(buf_users[i]));
                        strcpy((*users)[i],buf_users[i]);
                        (*uids)[i] = buf_uids[i];

                    }
                    free(buf_users);
                    free(buf_uids);
                    capacity+=10;
                }
            }
    }
    
    fclose(fusers);
    return PAM_SUCCESS;
}

int pam_get_uid(pam_handle_t *pamh, uid_t *uid, const char **nuser)
{
    const char *user = NULL;
    struct passwd *pw;
    
    /*Если не смогли получить имя пользователя выходим с ошибкой*/
    if((pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "pam_get_user: user?");
        return PAM_AUTH_ERR;
    }
    
    if(!user || !*user)
    {
        pam_syslog(pamh, LOG_ERR, "pam_get_user: user?");
        return PAM_AUTH_ERR;
    }

    if(!(pw = getpwnam(user)))
    {
        pam_syslog(pamh, LOG_ERR, "pam_get_uid; no such user");
        return PAM_USER_UNKNOWN;
    }
    
    /*Получаем uid пользователя*/
    *uid = pw->pw_uid;
    *nuser = user;
    return PAM_SUCCESS;
}


int get_faillog(pam_handle_t *pamh, uid_t *uid, struct faillog *f)
{
    FILE *logfile;
    
    /*Пытаемся открыть logfile на чтение*/
    if(!(logfile = fopen(DEFAULT_LOGFILE,"r")))
    {
        pam_syslog(pamh, LOG_ALERT, "Error opening %s for %s", logfile, "read");
        return PAM_AUTH_ERR;
    }
    
    /*Ставим указатель на запись пользователя*/
    if(fseek(logfile, (off_t) *uid * sizeof(struct faillog), SEEK_SET))
    {
        pam_syslog(pamh, LOG_ALERT, "fseek failed for %s", DEFAULT_LOGFILE);
        fclose(logfile);
        return PAM_AUTH_ERR;
    }
    
    fread((char*)&(*f), sizeof(struct faillog), 1, logfile);
    
    fclose(logfile);
    
    return PAM_SUCCESS;
}


int set_faillog(pam_handle_t *pamh, uid_t *uid, struct faillog *f)
{
    FILE *logfile;
    
    if(!(logfile = fopen(DEFAULT_LOGFILE,"r+")))
    {
        pam_syslog(pamh, LOG_ALERT, "Error opening %s for %s", logfile, "write");
        return PAM_AUTH_ERR;
    }
    
    if(fseek(logfile, (off_t) *uid * sizeof(struct faillog), SEEK_SET))
    {
        pam_syslog(pamh, LOG_ALERT, "fseek failed for %s", DEFAULT_LOGFILE);
        fclose(logfile);
        return PAM_AUTH_ERR;
    }
    
    (*f).fail_cnt += 1;
    (*f).fail_time = time(NULL);
    
    if(fwrite((char*)&(*f), sizeof(struct faillog), 1, logfile) == 0)
    {
        pam_syslog(pamh, LOG_ALERT, "update (fwrite) failed for %s", DEFAULT_LOGFILE);
        return PAM_AUTH_ERR;
    }
    
    fclose(logfile);
    
    return PAM_SUCCESS;
}

int check_count(pam_handle_t *pamh, int count)
{
    if(count >= MAX_COUNT)
    {
        pam_syslog(pamh, LOG_ERR, "Account locked due to %d fuiled logins", count);
        printf("Account locked due to %d fuiled logins\n", count);
        return PAM_AUTH_ERR;  
    }
    
    return PAM_SUCCESS;
}


int count_reset(pam_handle_t *pamh, uid_t *uid, struct faillog *f)
{
    FILE *logfile;
    
    if(!(logfile = fopen(DEFAULT_LOGFILE,"r+")))
    {
        pam_syslog(pamh, LOG_ALERT, "Error opening %s for %s", logfile, "write");
        return PAM_AUTH_ERR;
    }
    
    if(fseek(logfile, (off_t) *uid * sizeof(struct faillog), SEEK_SET))
    {
        pam_syslog(pamh, LOG_ALERT, "fseek failed for %s", DEFAULT_LOGFILE);
        fclose(logfile);
        return PAM_AUTH_ERR;
    }
    
    (*f).fail_cnt = 0;
    (*f).fail_time = 0;
    
    if(fwrite((char*)&(*f), sizeof(struct faillog), 1, logfile) == 0)
    {
        pam_syslog(pamh, LOG_ALERT, "update (fwrite) failed for %s", DEFAULT_LOGFILE);
        return PAM_AUTH_ERR;
    }
    
    fclose(logfile);
    
    return PAM_SUCCESS;
}

#define PAM_SM_AUTH
/*Увеличиваем значение на 1, независимо от того прошла аутентификация или нет*/
/*Если кол-во входов больше чем COUNT выходим с ошибкой*/
/*Если это админ, то выходим с усппехом(знаечение на 1 не увеличиваем)*/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv ) 
{
    
    const char *user;
	int retval;
    struct faillog f;
    uid_t uid;
    
    
    retval = pam_get_uid(pamh, &uid, &user);   
    if(retval != PAM_SUCCESS)
        return retval; 

    if(user_is_admin(pamh, &user))
        return PAM_SUCCESS;
    
    retval = get_faillog(pamh, &uid, &f);    
    if(retval != PAM_SUCCESS)
        return retval;
    
    retval = set_faillog(pamh, &uid, &f);
    if(retval != PAM_SUCCESS)
        return retval;
    
	return check_count(pamh, f.fail_cnt - 1);
}


PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    
	return PAM_SUCCESS;
}

#define PAM_SM_ACCOUNT
/*Сбрасываем счетчик если прошла аутентификация*/
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  
    const char *user;
    int retval;
    struct faillog f;
    uid_t uid;
    
   retval = pam_get_uid(pamh, &uid, &user);      
    if(retval != PAM_SUCCESS)
        return retval; 
    
    if(user_is_admin(pamh, &user))
    {
        char **users;
        uid_t *uids;
        int size;
         
        retval = get_users(pamh, &users, &uids, &size);
        if(retval != PAM_SUCCESS)
            return retval;
        
        time_t time = 0;
        
        int i;
        for(i = 0; i < size; ++i)
        {
            retval = get_faillog(pamh, &uids[i], &f);    
            if(retval != PAM_SUCCESS)
                return retval;
          
            if(f.fail_cnt >= MAX_COUNT)
            {
                if(time < f.fail_time)
                {
                    time = f.fail_time;
                    uid = uids[i];
                }
            }
        }
        if(time != 0)
        {
            retval = count_reset(pamh, &uid, &f);    
            if(retval != PAM_SUCCESS)
                return retval;
        }
    }
    else
    {
         retval = get_faillog(pamh, &uid, &f);    
        if(retval != PAM_SUCCESS)
            return retval;
    
        retval = count_reset(pamh, &uid, &f);    
        if(retval != PAM_SUCCESS)
            return retval;
    }
        
    
	return PAM_SUCCESS;
}
