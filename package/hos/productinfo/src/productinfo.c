/*******************************************************************************
  Copyright (c) 2012-2016, Autelan Networks. All rights reserved.
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sendfile.h>
#include <dirent.h>         /* opendir */
#include <errno.h>
#include <ctype.h>


#ifndef offsetof
# ifdef __builtin_offsetof
#  define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)
# else
#  define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
# endif
#endif

#define PRODUCTINFO_DIR     "/.productinfo/"
#define TEXTINFO_DIR        ".textinfo/"
#define PRDTINFO_FILE       ".prdtinfo"
#define PATHBUF_LEN         512
#define KEYBUF_SIZE         128
#define MAC_NAME            "mac"
#define MAC_NAME_COLON      "mac:"
#define CERT_TYPE           "certinfo"
#define CERT_DEST_DEFAULT   "/tmp/.certinfo/"
#define IMAGE_TYPE          "imginfo"
#define IMAGE_DEST_DEFAULT  "/tmp/.logo/"

/**
 * 修改请注意返回值， 成功命令行才返回0 echo $?检测
 */

#ifdef PRODUCT_WRITE
# define OPEN_MODE O_RDWR
#else
# define OPEN_MODE O_RDONLY
#endif


static int Usage(const char *program_name)
{
    fprintf(stderr, "%s: \n"
#ifdef PRODUCT_WRITE
            "\t set key value\n"
            "\t\t create or update a record\n"
            "\t\t eg: %s set mac 4C:48:DA:24:F0:00\n"
            "\t install resource type name\n"
            "\t\t install or update a resource by resource type and resource name, resource type will be created when first used\n"
            "\t\t eg: %s install resource " CERT_TYPE " default.ca\n"
            "\t\t eg: %s install resource " IMAGE_TYPE " logo.jpg\n"
            "\t delete key\n"
            "\t\t delete a record by key\n"
            "\t\t eg: %s delete mac\n"
            "\t delete resource type\n"
            "\t\t delete a resource type, all resources in this type will be deleted\n"
            "\t\t eg: %s delete resource " IMAGE_TYPE "\n"
            "\t\t eg: %s delete resource " CERT_TYPE "\n"
            "\t delete resource type name\n"
            "\t\t delete a resource by resource type and resource name, resource type won't be deleted\n"
            "\t\t eg: %s delete resource " CERT_TYPE " default.ca\n"
            "\t\t eg: %s delete resource " IMAGE_TYPE " image_name\n"
#endif
            "\t show\n"
            "\t\t show all records and resources\n"
            "\t\t eg: %s show\n"
            "\t show keys\n"
            "\t\t show all records (key-value pairs)\n"
            "\t\t eg: %s show keys\n"
            "\t show key\n"
            "\t\t show a record by key name\n"
            "\t\t eg: %s show mac\n"
            "\t show resources\n"
            "\t\t show all resources\n"
            "\t\t eg: %s show resources\n"
            "\t show resource type\n"
            "\t\t show resources in specified type\n"
            "\t\t eg: %s show resource " CERT_TYPE "\n"
            "\t\t eg: %s show resource " IMAGE_TYPE "\n"
            "\t show resource type name\n"
            "\t\t show resource by type and name\n"
            "\t\t eg: %s show resource " IMAGE_TYPE " logo.jpg\n"
            "\t get type name [path]\n"
            "\t\t get resource and put it into dest path\n"
            "\t\t eg: %s get " IMAGE_TYPE " logo.jpg \n"
            "\t\t eg: %s get " IMAGE_TYPE " logo.jpg /tmp/.logo/\n"
            "\t\t eg: %s get " CERT_TYPE " default.ca\n"
            "\t\t eg: %s get " CERT_TYPE " default.ca /tmp/.certinfo\n"
#ifdef PRODUCT_WRITE
            , program_name, program_name, program_name, program_name
            , program_name, program_name, program_name, program_name
#endif
            , program_name, program_name, program_name, program_name
            , program_name, program_name, program_name, program_name
            , program_name, program_name, program_name, program_name
            );
    return 1;
}
/* if path not exist, create it(ifdef PRODUCT_WRITE), make sure that parent exist */
static void prdt_path_check_and_create(const char *path, int dir1_file0)
{
    if(access(path, F_OK) == 0)
        return ;

	/* tmp下可以创建文件(否则(HOS-R20等中)获取imginfo的时候有bug), flash不允许 */
#ifndef PRODUCT_WRITE
	if(strncmp(path, "/tmp", 4) != 0)
		exit(1);
#endif

    if(dir1_file0 == 1)
    {
        if(mkdir(path, 0777) != 0)        /* mode = 0777,  real mode is (mode & ~umask & 0777) */
        {
            perror("mkdir");
            exit(1);
        }
    }
    else                                  /* create file */
    {
        int fd;
        if((fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU|S_IRWXO|S_IRWXG)) < 0)
        {
            perror("open");
            exit(1);
        }
        close(fd);
    }
}

#ifdef PRODUCT_WRITE
static int prdt_mac_valid(const char *mac)
{
    int i;
    if(strlen(mac) != 17)
        return 0;

    for(i = 0; i < 17; i++)
    {
        if(i % 3 == 2)
        {
            if(mac[i] == ':')
                continue;
        }
        else
        {
            if((mac[i] >= '0' && mac[i] <= '9')
                || (mac[i] >= 'a' && mac[i] <= 'f')
                || (mac[i] >= 'A' && mac[i] <= 'F')) 
                continue;
        }
        return 0;
    }
    return 1;
}
/*
 * 实际上不支持这么大的size,按照glibc文档,返回值和限制大小应该差1字节 '\0'
 * 后面-10是为了保险， 防止uclib的实现和glibc差别较大
 * value == NULL, 删除模式, 否则是set模式
 */
#define KEY_VALUE_RECORD_MAXSIZE    1024 
static int prdt_set_key_value(const char *key, const char *value)
{
    int fd;
    off_t size;
    char *buf;
    int new_len;       /* length of a line in product_info file */
    char *del_start, *del_end;
    char keybuf[KEYBUF_SIZE];

    if(key && (strcmp(key, "keys") == 0 || strcmp(key, "resources") == 0))
    {
        fprintf(stderr, "%s is a reserved name\n", key);
        exit(1);
    }

    if(strcmp(key, MAC_NAME) == 0 && value && !prdt_mac_valid(value))
    {
        fprintf(stderr, "%s is not a valid mac address\n", value);
        exit(1);
    }
    fd = open(PRODUCTINFO_DIR TEXTINFO_DIR PRDTINFO_FILE, OPEN_MODE);
    if(fd < 0)
    {
        perror("open");
        exit(1);
    }

    size = lseek(fd, 0, SEEK_END);
    if(size < 0 || size > 1024*1024)        /* assert(size <= 1024*1024) */
    {
        perror("lseek");
        exit(1);
    }

    if(size == 0 && value == NULL)
    {
        fprintf(stderr, "%s not exist\n", key);
        exit(1);
    }

    buf = malloc(size + (value ? KEY_VALUE_RECORD_MAXSIZE: 0));
    if(buf == NULL)
    {
        fprintf(stderr, " malloc error\n");
        exit(1);
    }
    (void)lseek(fd, 0, SEEK_SET);
    if(read(fd, buf, size) != size)
    {
        perror("read");
        exit(1);
    }

    buf[size] = 0;
    snprintf(keybuf, sizeof(keybuf), "\n%s:", key);
    if(strncmp(buf, &keybuf[1], strlen(&keybuf[1])) == 0)
        del_start = &buf[0];
    else
    {
        del_start = strstr(buf, keybuf);         /* strstr must be put before appending new string */
        if(del_start != 0)
            del_start++;                      /* jump '\n' */
    }

    new_len = 0;
    /* prepare input buf if in set mode, do nothing in delete mode */
    if(value)
    {
        new_len = snprintf(buf+size, KEY_VALUE_RECORD_MAXSIZE, "%s:%s\n", key, value);
        if(new_len < 0 || new_len > KEY_VALUE_RECORD_MAXSIZE -10)
        {
            fprintf(stderr, "snprintf %s new_len=%d\n", __func__, new_len);
            if(new_len > 0)
                fprintf(stderr, "input too long\n");
            exit(1);
        }
    }

    if(NULL == del_start)
    {
        if(value == NULL)
        {
            fprintf(stderr, "%s not found!\n", key);
            exit(1);
        }
        if(write(fd, buf+size, new_len) != new_len)
        {
            perror("write");
            exit(1);
        }
    }
    else            /* delete old line */
    {
        int write_len;

        del_end = strchr(del_start, '\n');
        del_end++;
        write_len = buf + size + new_len - del_end;  /* new_len == 0 in delete mode */

        if(ftruncate(fd, del_start - buf) != 0)      /* resize because the file could become smaller */
        {
            perror("ftruncate");
            exit(1);
        }

        size = lseek(fd, del_start - buf, SEEK_SET);
        if(size != del_start - buf)        /* assert(size <= 1024*1024) */
        {
            perror("lseek");
            exit(1);
        }

        if(write(fd, del_end, write_len) != write_len)
        {
            perror("write");
            exit(1);
        }
    }

    free(buf);
    close(fd);
    return 0;
}

static const char *prdt_basename(const char *p)
{
    const char *ret = NULL;
    while(p)
    {
        while(*p == '/')
            p++;
        if(*p == '\0')
            return ret;
        ret = p;
        p = strchr(p, '/');
    }
    return ret;
}

enum
{
    HANDLE_RESOURCE_INSTALL,
    HANDLE_RESOURCE_DELETE,
    HANDLE_RESOURCE_DELETE_TYPE,
};
/* if mode == HANDLE_RESOURCE_DELETE    make sure that src_file != NULL */
static int prdt_modify_resource(const char *type, const char *src_file, int mode)
{
    int fd_src, fd_dst, dir_len;
    struct stat sb;
    char dst_name_buf[PATHBUF_LEN];

    if(strcmp(type, "textinfo") == 0)
    {
        fprintf(stderr, "textinfo is reserved\n");
        exit(1);
    }
    if(sizeof(PRODUCTINFO_DIR)-1+strlen(type)+1/* / */
            +(src_file?strlen(prdt_basename(src_file)):0)+1 /* '\0' */ > PATHBUF_LEN)
    {
        fprintf(stderr, "input too long\n");
        exit(1);
    }
    strcpy(dst_name_buf, PRODUCTINFO_DIR);
    strcat(dst_name_buf, ".");
    strcat(dst_name_buf, type);
    dir_len = strlen(dst_name_buf);

    if(mode == HANDLE_RESOURCE_INSTALL)
        prdt_path_check_and_create(dst_name_buf, 1);                            /* check type(dir), parent dir exists */

    if(mode == HANDLE_RESOURCE_DELETE_TYPE)
    {
        DIR *dp;
        struct dirent *d;

        if((dp=opendir(dst_name_buf)) == NULL)
        {
            fprintf(stderr, "%s not exist\n", type);
            exit(1);
        }
        while((d=readdir(dp)) != NULL)
        {
            if(strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
                continue;
            strcat(dst_name_buf, "/");
            strcat(dst_name_buf, d->d_name);
            unlink(dst_name_buf);
            dst_name_buf[dir_len] = '\0';                                   /* restore parent dir */
        }
        if(rmdir(dst_name_buf) != 0)
        {
            perror("rmdir");
            exit(1);
        }
        closedir(dp);
        return 0;
    }

    strcat(dst_name_buf, "/");
    strcat(dst_name_buf, prdt_basename(src_file));

    if(mode == HANDLE_RESOURCE_DELETE)     /* delete a resource */
    {
        if(unlink(dst_name_buf) != 0)
        {
            fprintf(stderr, "%s or %s not exist\n", type, src_file);
            return 1;
        }
        return 0;
    }

    /* HANDLE_RESOURCE_INSTALL */

    prdt_path_check_and_create(dst_name_buf, 0);                            /* create file */

    fd_src = open(src_file, OPEN_MODE);
    fd_dst = open(dst_name_buf, OPEN_MODE);

    if(fd_src < 0 || fd_dst < 0)
    {
        perror("open");
        exit(1);
    }

    if(fstat(fd_src,&sb) != 0)
    {
        perror("fstat");
        exit(1);
    }

    {
        int l;
        off_t count = 0;
        char *cp_buf = malloc(4096);
        if(cp_buf == NULL)
        {
            fprintf(stderr, "malloc error\n");
            exit(1);
        }
        while(count != sb.st_size)
        {
            l = read(fd_src, cp_buf, sizeof(cp_buf));
            if(l < 0)
            {
                perror("read");
                exit(1);
            }
            l = write(fd_dst, cp_buf, l);
            if(l < 0)
            {
                perror("write");
                exit(1);
            }
            count += l;
        }
        free(cp_buf);
    }

    close(fd_src);
    close(fd_dst);
    return 0;
}
#endif

/* if key_name == NULL, show all */
static int prdt_show_keys(const char *key_name)
{
    int fd, i;
    char *buf, *_buf;
    off_t size;
    struct stat sb;

    fd = open(PRODUCTINFO_DIR TEXTINFO_DIR PRDTINFO_FILE, O_RDONLY);
    if(fd < 0)
    {
        perror("open");
        exit(1);
    }

    if(fstat(fd, &sb) != 0)
    {
        perror("fstat");
        exit(1);
    }
    size = sb.st_size;

    if(size == 0)                           /* malloc(0) return NULL in uClib */
    {
        if(key_name) 
            return 1;
        return 0;
    }

    _buf = malloc(size+1);
    if(_buf == NULL)
    {
        fprintf(stderr, "malloc error\n");
        exit(1);
    }

    *_buf= '\n';                            /* for strstr searching in first line */
    buf = _buf+1;

    if(read(fd, buf, size) != size)
    {
        perror("read");
        exit(1);
    }
    buf[size-1] = '\0';
    close(fd);

    if(key_name == NULL)
    {
        for(i = 0; i < size;i++)
        {
            char *p = &buf[i];
            if(strncmp(p, MAC_NAME_COLON, sizeof(MAC_NAME_COLON)-1) == 0)
            {
                int j;
                char *s;
                for(s = p + sizeof(MAC_NAME_COLON)-1, j = 0; j < 17; j++)
                {
                    if(j % 3 != 2)
                        s[j] = toupper(s[j]);
                }

            }
            if(buf[i] == ':')
            {
                char *newline = strchr(&buf[i+1], '\n');
                buf[i] = '=';
                if(newline == NULL)         /* the last newline has been replaced with '\n' */
                    break;
                i += newline - &buf[i];     /* buf[i] == '\n' */
            }
        }
        puts(buf);
    }
    else                                    /* show key-value by key name */
    {
        char *p, *newline;
        char keybuf[KEYBUF_SIZE];
        
        snprintf(keybuf, sizeof(keybuf), "\n%s:", key_name);
        p = strstr(_buf, keybuf);
        if(p == NULL)
        {
            free(_buf);
            return 1;
        }
        p++;

        if(strncmp(p, MAC_NAME_COLON, sizeof(MAC_NAME_COLON)-1) == 0)
        {
            int i;
            char *s;
            for(s = p + sizeof(MAC_NAME_COLON)-1, i = 0; i < 17; i++)
            {
                if(i % 3 != 2)
                    s[i] = toupper(s[i]);
            }
        }

        *(p+strlen(key_name)) = '=';
        newline = strchr(p, '\n');
        if(newline)
            *newline = '\0';

        puts(p);
    }
    free(_buf);
    return 0;
}

/* if type == NULL show all resources, if name == NULL  show all names */
static int prdt_show_resources(const char *type, const char *name)
{
    DIR *dp, *sub_dp;
    struct dirent *d, *sub_d;
    int path_len, not_found, nameMax;
    char path_buf[PATHBUF_LEN];
    char textinfo_dir_no_slash[] = TEXTINFO_DIR;
    struct dirent *result;

    textinfo_dir_no_slash[sizeof(TEXTINFO_DIR)-2] = '\0';     /* cut off '/' in the tail */

    strcpy(path_buf, PRODUCTINFO_DIR);
    path_len = strlen(path_buf);

    nameMax = pathconf(path_buf, _PC_NAME_MAX);                /* prepare for readdir_r */
    if (nameMax == -1)
    {
        fprintf(stderr, "pathconf error\n");
        exit(1);
    }

    d = malloc(offsetof(struct dirent, d_name) + nameMax + 1);                                                             
    if (d == NULL)
    {
        fprintf(stderr, "malloc error\n");
        exit(1);                                                                                                      
    }

    if((dp=opendir(path_buf)) == NULL)
    {
        fprintf(stderr, "path error\n");
        exit(1);
    }

    not_found = 1;
    while(1)
    {
        errno = readdir_r(dp, d, &result);
        if(errno != 0)
        {
            perror("readdir");
            exit(1);
        }
        if(result == NULL)
            break;

        if(type != NULL && strcmp(d->d_name+1, type) != 0)
            continue;
        if(strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
            continue;
        if(strcmp(d->d_name, textinfo_dir_no_slash) == 0)        /* not resources */
            continue;

        path_buf[path_len] = '\0';                                  /* restore parent dir */
        strcat(path_buf, d->d_name);

        /*********** subdir begin ************/
        if((sub_dp=opendir(path_buf)) == NULL)
        {
            fprintf(stderr, "line %d unexpected\n",  __LINE__);
            continue;
        }
        while((sub_d=readdir(sub_dp)) != NULL)
        {
            if(strcmp(sub_d->d_name, ".") == 0 || strcmp(sub_d->d_name, "..") == 0)
                continue;
            if(name != NULL && strcmp(sub_d->d_name, name) != 0)
                continue;
            not_found = 0;
            printf("resource:%s  type:%s\n", sub_d->d_name, d->d_name+1);
        }
        closedir(sub_dp);
        /*********** subdir end ************/
    }
    free(d);
    closedir(dp);

    if(not_found)
        return 1;
    return 0;
}

static int prdt_show(void)
{
    (void)prdt_show_keys(NULL);
    (void)prdt_show_resources(NULL, NULL);
    return 0;
}

int prdt_get_resource(const char *type, const char *name, const char *path)
{
    int l, ret;
    char cmd[PATHBUF_LEN*2];
    char dest[PATHBUF_LEN];
    char *ps, *pe;

    l = snprintf(cmd, sizeof(cmd), "cp -f %s.%s/%s ", PRODUCTINFO_DIR, type, name);

    if(path != NULL)
    {
        strncpy(dest, path, sizeof(dest));
        snprintf(&cmd[l], sizeof(cmd)-l, "%s/ >/dev/null 2>&1", path);
    }
    else
    {
        if(strcmp(type, CERT_TYPE) == 0)
        {
            strncpy(dest, CERT_DEST_DEFAULT, sizeof(dest));
            snprintf(&cmd[l], sizeof(cmd)-l, "%s/ >/dev/null 2>&1", CERT_DEST_DEFAULT);
        }
        else if(strcmp(type, IMAGE_TYPE) == 0)
        {
            strncpy(dest, IMAGE_DEST_DEFAULT, sizeof(dest));
            snprintf(&cmd[l], sizeof(cmd)-l, "%s/ >/dev/null 2>&1", IMAGE_DEST_DEFAULT);
        }
        else
        {
            fprintf(stderr, "destination path not specified\n");
            return 1;
        }
    }
    dest[sizeof(dest)-1] = 0;

    ps = dest;
    while(1)            /* mkdir -p */
    {
        pe = ps;
        while(*pe == '/')
            pe++;
        pe = strchr(pe, '/');
        if(pe == NULL)
        {
            prdt_path_check_and_create(dest, 1);
            break;
        }

        *pe = '\0';
        prdt_path_check_and_create(dest, 1);
        *pe = '/';
        ps = pe + 1;
    }

    ret = system(cmd);
    if(ret < 0)
        return 1;

    if(WEXITSTATUS(ret) != 0)
        fprintf(stderr, "not found\n");
    return WEXITSTATUS(ret);
}

int main(int argc, char *argv[])
{

#ifdef PRODUCT_WRITE
    mkdir("/overlay", 0777);
#endif
    system("mount|grep overlay >/dev/null || mount /dev/mtdblock4 /overlay -t jffs2 -o rw >/dev/null 2>&1");
    prdt_path_check_and_create(PRODUCTINFO_DIR, 1);                            /* check config dir */
    prdt_path_check_and_create(PRODUCTINFO_DIR TEXTINFO_DIR, 1);               /* check product_info dir */
    prdt_path_check_and_create(PRODUCTINFO_DIR TEXTINFO_DIR PRDTINFO_FILE, 0); /* check product_info file */

    if(argc < 2)
        return Usage(argv[0]); 

#ifdef PRODUCT_WRITE
    if(strcmp(argv[1], "set") == 0 && argc == 4)
        return prdt_set_key_value(argv[2], argv[3]);
    if(strcmp(argv[1], "install") == 0 && strcmp(argv[2], "resource") == 0 && argc == 5)
        return prdt_modify_resource(argv[3], argv[4], HANDLE_RESOURCE_INSTALL);

    if(strcmp(argv[1], "delete") == 0)
    {
        if(argc == 3)
            return prdt_set_key_value(argv[2], NULL);
        if(argc == 4 && strcmp(argv[2], "resource") == 0)
            return prdt_modify_resource(argv[3], NULL, HANDLE_RESOURCE_DELETE_TYPE);
        if(argc == 5 && strcmp(argv[2], "resource") == 0)
            return prdt_modify_resource(argv[3], argv[4], HANDLE_RESOURCE_DELETE);
    }
#endif

    if(strcmp(argv[1], "show") == 0)
    {
        if(argc == 5 && strcmp(argv[2], "resource") == 0)
            return prdt_show_resources(argv[3], argv[4]);
        if(argc == 4 && strcmp(argv[2], "resource") == 0)
            return prdt_show_resources(argv[3], NULL);
        if(argc == 3)
        {
            if(strcmp(argv[2], "keys") == 0)
                return prdt_show_keys(NULL);
            else if(strcmp(argv[2], "resources") == 0)
                return prdt_show_resources(NULL, NULL);
            else
                return prdt_show_keys(argv[2]);
        }
        if(argc == 2)
            return prdt_show();
    }

    if(strcmp(argv[1], "get") == 0)
    {
        if(argc == 4)
            return prdt_get_resource(argv[2], argv[3], NULL);
        if(argc == 5)
            return prdt_get_resource(argv[2], argv[3], argv[4]);
    }

    return Usage(argv[0]);
}

/******************************************************************************/
