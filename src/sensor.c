/*
 * Project: ZK-Sentinel (The Eye)
 * Standard: NASA JPL "Power of Ten" Safety Critical Rules
 * Description: Hardened sensor that vectorizes inputs into 2D features (Hash, Length).
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <assert.h>
 
 #define PORT 8888
 #define BUFFER_SIZE 1024
 #define MAX_CONNECTIONS 1000 
 
 #define SAFE_ASSERT(cond, msg) \
     do { \
         if (!(cond)) { \
             fprintf(stderr, "ASSERT FAIL: %s\n", msg); \
             exit(EXIT_FAILURE); \
         } \
     } while (0)
 
 static unsigned long vectorize_input(const char *data, size_t len) {
     unsigned long hash = 5381;
     size_t i;
     SAFE_ASSERT(data != NULL, "Null data input");
     
     for (i = 0; i < len && i < BUFFER_SIZE; i++) {
         hash = ((hash << 5) + hash) + (unsigned char)data[i];
     }
     return hash;
 }
 
 static void handle_connection(int client_fd) {
     char buffer[BUFFER_SIZE] = {0};
     ssize_t bytes_read;
     unsigned long threat_hash;
 
     bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
 
     if (bytes_read > 0) {
         buffer[bytes_read] = '\0';
         threat_hash = vectorize_input(buffer, (size_t)bytes_read);
 
         /* Output 2D Vector: [Hash, Length] */
         fprintf(stdout, "{\"v\": [%lu, %zd]}\n", threat_hash, bytes_read);
         fflush(stdout); /* CRITICAL: Push to Python immediately */
     } 
     close(client_fd);
 }
 
 int main(void) {
     int server_fd, new_socket;
     struct sockaddr_in address;
     int addrlen = sizeof(address);
     int opt = 1;
     int i; 
 
     server_fd = socket(AF_INET, SOCK_STREAM, 0);
     SAFE_ASSERT(server_fd >= 0, "Socket creation failed");
 
     setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
     
     address.sin_family = AF_INET;
     address.sin_addr.s_addr = INADDR_ANY;
     address.sin_port = htons(PORT);
 
     if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
         perror("Bind failed");
         exit(EXIT_FAILURE);
     }
 
     listen(server_fd, 3);
     fprintf(stderr, "[*] ZK-Sentinel SENSOR active on port %d...\n", PORT);
 
     for (i = 0; i < MAX_CONNECTIONS; i++) {
         new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
         if (new_socket >= 0) {
             handle_connection(new_socket);
         }
     }
 
     close(server_fd);
     return 0;
 }