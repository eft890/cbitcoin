// Include standard libraries.
#include <netinet/in.h>
#include <stdio.h>
#include <readline/readline.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

// Include cbitcoin libraries.
#include <CBVersion.h>
#include <CBAssociativeArray.h>
#include <CBPeer.h>
#include <CBMessage.h>
#include <CBNetworkAddress.h>

// Default satoshi port.
#define DEFAULT_PORT 28333

// Netmagic to add to message headers.
#define NETMAGIC 0xd0b4bef9

// Initial client address.
const uint8_t test_addr[4] = {25, 126, 8, 128};

// Enum of CB message header size variables.
typedef enum {
	CB_MESSAGE_HEADER_NETWORK_ID = 0,
	CB_MESSAGE_HEADER_TYPE = 3,
	CB_MESSAGE_HEADER_LENGTH = 16,
	CB_MESSAGE_HEADER_CHECKSUM = 20,
} CBMessageHeaderOffsets;

// Global associative array variable. Holds all connected clients.
CBAssociativeArray peerSocks;
// Associative array element struct. Holds bookkeeping variables per client.
typedef struct {
	uint32_t addr;
	unsigned int socket;
	short version;
} peerSocksElement;

bool running = true;

// Helper function definitions.
CBCompare compare_pbes(void *key1, void *key2);
int connect_client(uint32_t address, uint16_t port);
void send_version(int socket);
void *command_loop(void *arg);
void handle_command(char *cmd);
void receive_message(int socket);

int main() {
	CBPosition iter; // associative array iteration placeholder
	pthread_t command_thread;	// handler to command loop thread

	// Initialize the associative array.
	CBInitAssociativeArray(&peerSocks, compare_pbes, NULL);

	// Setup the initial connection.
	connect_client((((((test_addr[0] << 8) | test_addr[1]) << 8) | test_addr[2]) << 8) | test_addr[3], DEFAULT_PORT);

	// Declare local vars for select.
	int maxDescriptor;		// max file descriptor number
	fd_set inSocks, outSocks;	// socket set for reading and writing
	char *line = NULL;		// line read in from stdin

	// Create command loop thread.
	if (pthread_create(&command_thread, NULL, command_loop, NULL)) {
		printf("Error creating command thread.\n");
		return -1;
	}

	// Loop while client is running.
	while (running) {
		// Zero socket sets.
		FD_ZERO(&inSocks);
		FD_ZERO(&outSocks);

		// Iterate through associative array elements and add sockets to socket set.
		CBAssociativeArrayGetFirst(&peerSocks, &iter);
		do {
			unsigned int sock = ((peerSocksElement *)(iter.node->elements[iter.index]))->socket;
			if (sock > maxDescriptor) maxDescriptor = sock;
			FD_SET(sock, &inSocks);
			FD_SET(sock, &outSocks);
		} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

		// Setup timeout timeval.
		struct timeval timeout;
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;

		// Call select.
		if (select(maxDescriptor + 1, &inSocks, &outSocks, NULL, &timeout) != 0) {
			// Iterate through associative array elements and check if there is data to read or write.
			CBAssociativeArrayGetFirst(&peerSocks, &iter);
			do {
				peerSocksElement *pse = (peerSocksElement *)(iter.node->elements[iter.index]);
				unsigned int sock = pse->socket;

				if (FD_ISSET(sock, &outSocks)) {
					if (pse->version == 0) {
						pse->version = 1;
						send_version(sock);
					}
				}

				// if (FD_ISSET(sock, &inSocks)) {
				// 	receive_message(sock);
				// }
			} while (!CBAssociativeArrayIterate(&peerSocks, &iter));
		}
	}

	if (pthread_join(command_thread, NULL)) {
		printf("Error joining threads.\n");
		return -1;
	}

	CBAssociativeArrayGetFirst(&peerSocks, &iter);
	do {
		unsigned int sock = ((peerSocksElement *)(iter.node->elements[iter.index]))->socket;
		close(sock);
	} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

	return 0;
}

CBCompare compare_pbes(void *key1, void *key2) {
	peerSocksElement *pbe1, *pbe2;
	pbe1 = (peerSocksElement *)key1;
	pbe2 = (peerSocksElement *)key2;

	if (pbe1->socket != 0 && pbe2->socket != 0) {
		if (pbe1->socket < pbe2->socket) return CB_COMPARE_LESS_THAN;
		else if (pbe1->socket > pbe2->socket) return CB_COMPARE_MORE_THAN;
		else return CB_COMPARE_EQUAL;
	} else if (pbe1->addr != 0 && pbe2->addr != 0) {
		if (pbe1->addr < pbe2->addr) return CB_COMPARE_LESS_THAN;
		else if (pbe1->addr > pbe2->addr) return CB_COMPARE_MORE_THAN;
		else return CB_COMPARE_EQUAL;
	} else {
		return -1;
	}
}

int connect_client(uint32_t address, uint16_t port) {
	int sock;
	struct sockaddr_in addr;
	peerSocksElement *pse;
	CBPosition root;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error creating client socket.");
		exit(-1);
	}

	memset(&addr, sizeof(addr), 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = address;

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Error connecting to client.");
		exit(-1);
	}

	pse = malloc(sizeof(peerSocksElement));
	pse->addr = address;
	pse->socket = sock;
	pse->version = 0;
	if (!CBAssociativeArrayGetLast(&peerSocks, &root)) {
		root.node = peerSocks.root;
		root.index = 0;
	}
	CBAssociativeArrayInsert(&peerSocks, pse, root, (CBBTreeNode *)NULL);

	// send_version(sock);

	return sock;
}

void send_version(int socket) {
	CBByteArray *pip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, test_addr[0], test_addr[1], test_addr[2], test_addr[3]}, 16);
    CBNetworkAddress *peeraddr = CBNewNetworkAddress(0, pip, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
    CBPeer *peer = CBNewPeerByTakingNetworkAddress(peeraddr);

	CBByteArray *sip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
    CBByteArray *ua = CBNewByteArrayFromString("cmsc417versiona", '\00');
    CBNetworkAddress * sourceAddr = CBNewNetworkAddress(0, sip, 0, CB_SERVICE_FULL_BLOCKS, false);

    int32_t vers = 70001;
    int nonce = rand();
    CBVersion * version = CBNewVersion(vers, CB_SERVICE_FULL_BLOCKS, time(NULL), &peer->base, sourceAddr, nonce, ua, 0);
    CBMessage *message = CBGetMessage(version);

    char header[24];
    memcpy(header + CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12);

    /* Compute length, serialized, and checksum */
    uint32_t len = CBVersionCalculateLength(version);
    message->bytes = CBNewByteArrayOfSize(len);
    len = CBVersionSerialise(version, false);
    if (message->bytes) {
        // Make checksum
        uint8_t hash[32];
        uint8_t hash2[32];
        CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
        CBSha256(hash, 32, hash2);
        message->checksum[0] = hash2[0];
        message->checksum[1] = hash2[1];
        message->checksum[2] = hash2[2];
        message->checksum[3] = hash2[3];
    }
    CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
    CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);
    // Checksum
    memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);

    // Send the header
    send(socket, header, 24, 0);
    
    // Send the message
    printf("message len: %d\n", message->bytes->length);
    printf("checksum: %x\n", *((uint32_t *) message->checksum));
    send(socket, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length, 0);
    // print_hex(message->bytes);
}

void *command_loop(void *arg) {
	char *line = NULL;

	while (true) {
		line = readline("Enter command: ");

		if (!line || !*line) {
			free(line);
			continue;
		}

		if (!strcmp(line, "exit") || !strcmp(line, "quit")) {
			running = false;
			free(line);
			return 0;
		}

		add_history(line);
		free(line);
	}

	return 0;
}

void handle_command(char *cmd) {
	if (!strcmp(cmd, "")) {
		return;
	}

	return;
}

void receive_message(int socket) {
	// Message local variables.
	char header[24];	// header data

	// Read message header from socket.
	recv(socket, header, 24, 0);
	printf("%s\n", header);
	return;
	if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
		printf("Wrong netmagic.\n");
		return;
	}

	// Read message payload.
	unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
	char *payload = (char *)malloc(length);
	socklen_t nread = 0;
	if (length) {
		if ((nread = recv(socket, payload, length, 0)) != length) {
			printf("Incomplete read: %u bytes received when %u bytes expected", nread, length);
		}
	}

	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
		peerSocksElement pse;
		pse.addr = 0;
		pse.socket = socket;
		CBFindResult find = CBAssociativeArrayFind(&peerSocks, &pse);
		((peerSocksElement *)(find.position.node->elements[find.position.index]))->version = 2;
		printf("received verack header\n");
	}
}
