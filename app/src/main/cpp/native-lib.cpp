#include <jni.h>
#include <string>
#include <zconf.h>
#include <sys/ptrace.h>
#include <sys/inotify.h>
#include<Android/log.h>
#include <dirent.h>
#include <elf.h>

#define TAG "antiDebug" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型



extern "C" JNIEXPORT jstring JNICALL
Java_com_yusakul_androidantidebug_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}




//从maps中读取elf文件在内存中的起始地址
unsigned long GetLibAddr(char * name) {
    unsigned long ret = 0;

    char buf[4096], *temp;
    int pid;
    FILE *fp;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        puts("open failed");
        goto _error;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, name)) {
            temp = strtok(buf, "-");//将buf由"-"参数分割成片段
            ret = strtoul(temp, NULL, 16);//将字符串转换成unsigned long(无符号长整型数)
            break;
        }
    }
    _error:
    fclose(fp);
    return ret;
}


//方法一：附加到自身 让ida附加不上 无法实现调试
extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug01( JNIEnv *env, jobject /* this */)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    LOGD("%s", "antidebug01 run");
    LOGD("--------------------------");
}

//方法二：检测TracerPid的值 如果不为0 说明正在被调试
extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug02( JNIEnv *env, jobject /* this */)
{
    LOGD("%s", "antidebug02 start");
    const int bufsize = 1024;
    char filename[bufsize];
    char line[bufsize];
    int pid = getpid();//getpid ()用来取得目前进程的进程识别码，许多程序利用取到的此值来建立临时文件， 以避免临时文件相同带来的问题。
    FILE *fp;
    sprintf(filename, "proc/%d/status", pid);
    fp = fopen(filename, "r");//
    if (fp != NULL) {
        while (fgets(line, bufsize, fp)) {
            if (strncmp(line, "TracerPid", 9) == 0) {
                int status = atoi(&line[10]);//第10为转成整数
                if (status != 0) {
                    fclose(fp);//先关闭
                    LOGD("%s", "antidebug02 run, TracerPid not 0, exit");
                    int ret = kill(pid, SIGKILL);
                }
                break;
            }
            LOGD("%s", "antidebug02 run, not find TracerPid");
        }
    }
    LOGD("--------------------------");
}

//方法三：检测常用的端口
extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug03( JNIEnv *env, jobject /* this */)
{
    LOGD("%s", "antidebug03 start");

    const int bufsize = 1024;
    char filename[bufsize];
    char line[bufsize];
    int pid = getpid();
    FILE *fp;
    sprintf(filename, "proc/net/tcp");
    fp = fopen(filename, "r");//
    if (fp != NULL) {
        while (fgets(line, bufsize, fp)) {
            if (strncmp(line, "5D8A", 4) == 0) {  //即23946, IDA调试服务的默认端口
                LOGD("%s", "antidebug03 run, find port 23946, exit");
                int ret = kill(pid, SIGKILL);
            }
        }
    }
    fclose(fp);//关闭流
    LOGD("--------------------------");
}


//第四种检测是否存在android_server 判断是否正在被调试  这里要有读取目录的权限
extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug04( JNIEnv *env, jobject /* this */)
{
    LOGD("%s", "antidebug04 start");

    const char *rootPath = "/data/local/tmp";
    LOGD("%s", "read dir");
    DIR *dir;
    dir = opendir(rootPath);
    LOGD("%s", "read /data/local/tmp finsh");
    if (dir != NULL) {
        dirent *currentDir;
        while ((currentDir = readdir(dir)) != NULL) {
            //readdir()方法就像java中迭代器的next()方法一样
            //currentDir->d_name; //文件名，目录名
            //currentDir->d_type; //类型，是目录还是文件啥的
            if (strncmp(currentDir->d_name, "android_server", 14) == 0) {
                LOGD("%s", currentDir->d_name);
                LOGD("%s", "antidebug04 run android_server exit  the programe exit");
            }
        }
        closedir(dir); //用完要关掉，要不然会出错
    } else {
        LOGD("%s", "dir not access");
    }
    LOGD("--------------------------");
}



/**
 * 第五种：检测在调试状态下的软件断点
 * 读取其周围的偏移地址有没有ARM等指令集的断点指令
 * 遍历so中可执行segment，查找是否出现breakpoint指令即可
 **/

extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug05( JNIEnv *env, jobject /* this */)
{
    LOGD("%s", "antidebug05 start");

    Elf32_Ehdr *elfhdr;
    Elf32_Phdr *pht;
    unsigned int size, base, offset, phtable;
    int n, i, j;
    char *p;
    //从maps中读取elf文件在内存中的起始地址
    char name[] = "libnative-lib.so";
    base = GetLibAddr(name);
    if (base == 0) {
        LOGD("find base error/n");
        return;
    }
    elfhdr = (Elf32_Ehdr *) base;

    phtable = elfhdr->e_phoff + base;   //程序头部表

    for (i = 0; i < elfhdr->e_phnum; i++) {     //程序头部表 表项数量
        //LOGD("进入程序头表遍历循环");
        pht = (Elf32_Phdr * )(phtable + i * sizeof(Elf32_Phdr));

        if (pht->p_flags & PF_X || pht->p_flags & PF_R || pht->p_flags & PF_W) //段标志 可执行 读 写
        {
            //LOGD("进入段分析");
            offset =
                    pht->p_vaddr + base + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * elfhdr->e_phnum;
            LOGD("offset:%X ,len:%X", offset, pht->p_memsz);

            p = (char *) offset;
            size = pht->p_memsz;
           //LOGD("拿到段在内存中的长度");
           // LOGD("随后开始遍历段中是否有断点");
            for (j = 0, n = 0; j < size; ++j, ++p) {

                if (*p == 0x10 && *(p + 1) == 0xde) {
                    n++;
                    LOGD("### find thumb bpt %X /n", p);

                } else if (*p == 0xf0 && *(p + 1) == 0xf7 && *(p + 2) == 0x00 && *(p + 3) == 0xa0) {
                    n++;
                    LOGD("### find thumb2 bpt %X /n", p);
                } else if (*p == 0x01 && *(p + 1) == 0x00 && *(p + 2) == 0x9f && *(p + 3) == 0xef) {
                    n++;
                    LOGD("### find arm bpt %X /n", p);
                }
            }
            LOGD("### find breakpoint num: %d/n", n);
        }
    }
    LOGD("--------------------------");
}

/**
 * 方法六：inotify检测
 * 通过inotify监控/proc/pid文件夹下的关键文件变化（maps的读，mem的读等），
 * 若想查看某进程的的虚拟地址空间或者想dump内存，则会触发打开或读取的事件，
 * 只要接收到这些事件，则说明进程正在被调试，直接kill主进程
 **/
extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug06( JNIEnv *env, jobject /* this */)
{
    LOGD("%s", "antidebug06 start");

    const int MAXLEN = 2048;
    int ppid = getpid();
    char buf[1024], readbuf[MAXLEN];
    int pid, wd, ret, len, i;
    int fd;
    fd_set readfds;
    //防止调试子进程
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    fd = inotify_init();
    sprintf(buf, "/proc/%d/maps", ppid);
    //LOGD("buf:%s", buf);

    //监控整个目录子树内的事件
    //wd = inotify_add_watch(fd, "/proc/self/mem", IN_ALL_EVENTS);
    wd = inotify_add_watch(fd, buf, IN_ALL_EVENTS);

    /*
     * 读取/proc/self/maps可以得到当前进程的内存映射关系，通过读该文件的内容可以得到内存代码段基址。
     * /proc/self/mem是进程的内存内容，通过修改该文件相当于直接修改当前进程的内存。
     */

    if (wd < 0) {
        LOGD("can't watch %s", buf);
        return;
    }
    //LOGD("开始循环检查");
    while (1) {
        i = 0;
        //注意要对fd_set进行初始化
        FD_ZERO(&readfds); /*将readfds清零使集合中不含任何fd*/
        FD_SET(fd, &readfds); /*将fd加入readfds集合*/

        //第一个参数固定要+1，第二个参数是读的fdset，第三个是写的fdset，最后一个是等待的时间
        //最后一个为NULL则为阻塞
        //select系统调用是用来让我们的程序监视多个文件句柄的状态变化
        //LOGD("获取检查结果");
        ret = select(fd + 1, &readfds, 0, 0, 0);
        if (ret == -1)
            break;

        //LOGD("分发检查结果");
        if (ret) {
            len = read(fd, readbuf, MAXLEN);
            while (i < len) {
                //返回的buf中可能存了多个inotify_event
                struct inotify_event *event = (struct inotify_event *) &readbuf[i];
                LOGD("event mask %d\n", (event->mask & IN_ACCESS) || (event->mask & IN_OPEN)); //文件读取操作 文件被打开
                //这里监控读和打开事件
                if ((event->mask & IN_ACCESS) || (event->mask & IN_OPEN)) {
                    LOGD("kill!!!!!\n");
                    //事件出现则杀死父进程
                    int ret = kill(ppid, SIGKILL);
                    LOGD("ret = %d", ret);
                    return;
                }
                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    LOGD("--------------------------");
}

//方法七：检测代码执行时间差
int gettimeofday(struct timeval *tv, struct timezone *tz);

extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_antidebug07( JNIEnv *env, jobject /* this */)
{
    LOGD("%s", "antidebug07 start");

    int pid = getpid();
    struct timeval t1;
    struct timeval t2;
    struct timezone tz;
    gettimeofday(&t1, &tz);
    gettimeofday(&t2, &tz);
    int timeoff = (t2.tv_sec) - (t1.tv_sec);
    if (timeoff > 1) {
        LOGD("%s", "antidebug07: timeoffset > 1s, exit");
        int ret = kill(pid, SIGKILL);
        return;
    }
    LOGD("--------------------------");
}


//===================================================================================================================
// 其他：

// 遍历linker.so导出表, 检查rtld_db_dlactivity地址是否为断点 类似于方法5
// 另外，字符串尽可能的做加密处理动态解密获取，否则容易顺藤摸瓜找到反调试点

/**
 * 检测特定函数中是否存在断点指令
 * @param addr
 * @param size
 * @return true 发现断点指令 false 未发现断点指令
 */
bool checkBreakPointCMD(unsigned char* addr, unsigned long int size) {
    int pid = getpid();

    // arm架构cpu断点指令
    unsigned char armBkpt[4] = { 0 };
    armBkpt[0] = 0xf0;
    armBkpt[1] = 0x01;
    armBkpt[2] = 0xf0;
    armBkpt[3] = 0xe7;
    //thumb指令集断点指令
    unsigned char thumbBkpt[2] = { 0 };
    thumbBkpt[0] = 0x10;
    thumbBkpt[1] = 0xde;
    // 判断模式
    int mode = (unsigned long int) addr % 2;
    if (1 == mode) {
        LOGD("checkbkpt:(thumb mode)该地址为thumb模式");
        unsigned char* start = (unsigned char*) ((unsigned long int) addr - 1);
        unsigned char* end = (unsigned char*) ((unsigned long int) start + size);
        // 遍历对比
        while (1) {
            if (start >= end) {
                LOGD("checkbkpt:(no find bkpt)没有发现断点.");
                break;
            }
            if (0 == memcmp(start, thumbBkpt, 2)) {
                LOGD("checkbkpt:(find it)发现断点.");
                return  kill(pid, SIGKILL);
            }
            start = start + 2;
        }
    } else {
        LOGD("checkbkpt:(arm mode)该地址为arm模式");
        unsigned char* start =  addr;
        unsigned char* end = (unsigned char*) ((unsigned long int) start + size);
        // 遍历对比
        while (1) {
            if (start >= end) {
                LOGD("checkbkpt:(no find)没有发现断点.");
                break;
            }
            if (0 == memcmp(start, armBkpt, 4)) {
                LOGD("checkbkpt:(find it)发现断点.");
                return  kill(pid, SIGKILL);
            }
            start = start + 4;
        }
    }
    return false;
}


/**
 * 判断当前是否存在调试进程
 * @return
 */

extern "C" JNIEXPORT void JNICALL
Java_com_yusakul_androidantidebug_MainActivity_FindDebugProcess( JNIEnv *env, jobject /* this */)
{
    int pid = getpid();

    FILE* pfile = NULL;
    char buf[0x1000] = { 0 };
    pfile = popen("ps", "r");
    if (NULL == pfile) {
        LOGD("ps could not find");
        return ;
    }
    while (fgets(buf, sizeof(buf), pfile)) {
        // 查找子串
        char* strA = NULL;
        char* strB = NULL;
        char* strC = NULL;
        char* strD = NULL;
        char* strE = NULL;
        strA = strstr(buf, "android_server");
        strB = strstr(buf, "gdbserver");
        strC = strstr(buf, "gdb");
        strD = strstr(buf, "fuwu");
        strE = strstr(buf, "android_ser");
        if (strA || strB || strC || strD || strE) {
            pclose(pfile);
            LOGD("DebugProcess find");
            kill(pid, SIGKILL);
            return ;
        }
    }
    pclose(pfile);
    LOGD("DebugProcess does not find");
    return ;
}

