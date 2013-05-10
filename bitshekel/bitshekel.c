// Include standard libraries.
#include <netinet/in.h>
#include <stdio.h>
#include <readline/readline.h>
#include <pthread.h>
#include <sys/select.h>
#include <unistd.h>

// Include cbitcoin libraries.
#include <CBVersion.h>
#include <CBAssociativeArray.h>
#include <CBPeer.h>
#include <CBMessage.h>
#include <CBNetworkAddress.h>
#include <CBChainDescriptor.h>
#include <CBGetBlocks.h>
#include <CBBlock.h>
#include <CBFullValidator.h>
#include <CBDependencies.h>
#include <CBInventoryItem.h>

// Client version.
#define VERSION 70001

// Default satoshi port.
#define DEFAULT_PORT 28333

// Netmagic to add to message headers.
#define NETMAGIC 0xd0b4bef9		// umdnet netmagic

// Initial client address.
uint8_t main_server[4] = {128, 8, 126, 25};

// Enum of CB message header size variables.
typedef enum {
	CB_MESSAGE_HEADER_NETWORK_ID = 0,
	CB_MESSAGE_HEADER_TYPE = 4,
	CB_MESSAGE_HEADER_LENGTH = 16,
	CB_MESSAGE_HEADER_CHECKSUM = 20,
} CBMessageHeaderOffsets;

// Global associative array variable. Holds all connected clients.
CBAssociativeArray peerSocks;

// Global getblocks and chain descriptor variables.
CBGetBlocks getBlocks;
CBChainDescriptor chainDesc;

// Global full validator and block chain storage variables.
CBFullValidator fullVal;
uint64_t bcStorage;
bool badBCS;

// Shared running variable.
bool running = true;

// Helper function definitions.
CBCompare compare_peers(void *key1, void *key2);
void *command_loop(void *arg);
void handle_command(char *cmd);
void connect_client(uint8_t address[4], uint16_t port);
void send_version(CBPeer *peer);
void send_getaddr(CBPeer *peer);
void send_getblocks(CBPeer *peer);
void receive_message(CBPeer *peer);
void parse_addr(uint8_t *addr_list);
void parse_inv(uint8_t *inv_list);

/**
 * Main bitshekel client entry point.
 */
int main() {
	CBBlock *initBlock; // Initial block to add to chain descriptor.
	uint8_t initBlockHash[32]; // Pointer to store initial block's hash.
	CBByteArray *initBlockHashByteArray; // Byte array of block hash.
	CBByteArray *hashStop; // Byte array of hash stop.
	CBPosition iter; // associative array iteration placeholder
	pthread_t command_thread;	// handler to command loop thread

	// Initialize the associative array.
	if (!CBInitAssociativeArray(&peerSocks, compare_peers, NULL)) {
		printf("Error initializing associative array.\n");
	}

	// Initialize chain desc and get blocks.
	if (!CBInitChainDescriptor(&chainDesc)) {
		printf("Error initializing chain descriptor.\n");
	}
	hashStop = CBNewByteArrayOfSize(4);
	CBByteArraySetInt32(hashStop, 0, 0);
	if (!CBInitGetBlocks(&getBlocks, VERSION, &chainDesc, hashStop)) {
		printf("Error initializing get blocks.\n");
	}

	// Setup full validator and block chain storage.
	bcStorage = CBNewBlockChainStorage("./shekel");
	CBInitFullValidator(&fullVal, bcStorage, &badBCS, (CBFullValidatorFlags)NULL);

	// Get genesis block, calculate hash, add to chain descriptor.
	initBlock = CBNewBlock();
	CBInitBlockGenesisUMDNet(initBlock);
	CBBlockCalculateHash(initBlock, initBlockHash);
	initBlockHashByteArray = CBNewByteArrayWithDataCopy(initBlockHash, 32);
	CBChainDescriptorAddHash(&chainDesc, initBlockHashByteArray);

	// Setup the initial connection.
	connect_client(main_server, DEFAULT_PORT);

	// Declare local vars for select.
	int max_desc = -1;	// max file descriptor number
	fd_set inSocks, outSocks;	// socket set for reading and writing

	// Create command loop thread.
	if (pthread_create(&command_thread, NULL, command_loop, NULL)) {
		printf("Error creating command thread.\n");
		return -1;
	}

	bool sendgetblocks = false;

	// Loop while client is running.
	while (running) {
		// Zero socket sets.
		FD_ZERO(&inSocks);
		FD_ZERO(&outSocks);

		// Iterate through associative array elements and add sockets to socket set.
		CBAssociativeArrayGetFirst(&peerSocks, &iter);
		do {
			int sock = ((CBPeer *)(iter.node->elements[iter.index]))->socketID;
			FD_SET(sock, &inSocks);
			FD_SET(sock, &outSocks);
			if (sock > max_desc) max_desc = sock;
		} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

		// Setup timeout timeval.
		struct timeval timeout;
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;

		// Call select.
		if (select(max_desc + 1, &inSocks, &outSocks, NULL, &timeout) != 0) {
			// Iterate through associative array elements and check if there is data to read or write.
			do {
				CBPeer *peer = (CBPeer *)(iter.node->elements[iter.index]);
				int sock = peer->socketID;

				if (FD_ISSET(sock, &outSocks)) {
					if (peer->versionAck) {
						if (!peer->getAddresses) {
							send_getaddr(peer);
						}
						if (!sendgetblocks) {
							sendgetblocks = true;
							send_getblocks(peer);
						}
					}
				}

				if (FD_ISSET(sock, &inSocks)) {
					receive_message(peer);
				}
			} while (!CBAssociativeArrayIterate(&peerSocks, &iter));
		}
	}

	// Join command loop thread.
	if (pthread_join(command_thread, NULL)) {
		printf("Error joining threads.\n");
		return -1;
	}

	// Loop through and close sockets.
	CBAssociativeArrayGetFirst(&peerSocks, &iter);
	do {
		CBPeer *peer = (CBPeer *)(iter.node->elements[iter.index]);
		close(peer->socketID);
		CBReleaseObject(peer);
	} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

	// Free associative array.
	CBFreeAssociativeArray(&peerSocks);

	return 0;
}

/**
 * Custom CBAssociativeArray comparison function.
 * key1: First key to compare.
 * key2: Second key to compare.
 * returns: Comparison result of the two keys.
 */
CBCompare compare_peers(void *key1, void *key2) {
	// Cast keys to peers.
	CBPeer *peer1, *peer2;
	peer1 = (CBPeer *)key1;
	peer2 = (CBPeer *)key2;

	// If either of the peers doesn't have a socket (probably searching by address)
	if (peer1->socketID == -1 || peer2->socketID == -1) {
		// Compare the addresses.
		if (CBNetworkAddressEquals(&(peer1->base), &(peer2->base))) return CB_COMPARE_EQUAL;
		else if (peer1->socketID == -1) return CB_COMPARE_LESS_THAN;
		else if (peer2->socketID == -1) return CB_COMPARE_MORE_THAN;
		else return -1;
	}

	// Check if the sockets match.
	if (peer1->socketID < peer2->socketID) return CB_COMPARE_LESS_THAN;
	else if (peer1->socketID > peer2->socketID) return CB_COMPARE_MORE_THAN;
	else return CB_COMPARE_EQUAL;
}

/**
 * Entry point for command loop thread.
 * arg: Argument sent in on invocation of new thread.
 */
void *command_loop(void *arg) {
	// Local variables.
	char *line = NULL;	// Pointer to line read in.

	// Loop while client is running.
	while (running) {
		// Read the next line.
		line = readline("Enter command: ");

		// If the line is empty, free and continue loop.
		if (!line || !*line) {
			free(line);
			continue;
		}

		// If we said to exit, switch the running variable and continue to exit.
		if (!strcmp(line, "exit") || !strcmp(line, "quit")) {
			running = false;
			free(line);
			continue;
		}

		// Pass the command to the command helper.
		handle_command(line);

		// Add the line to history and free.
		add_history(line);
		free(line);
	}

	return 0;
}

/**
 * Helper function. Handles commands from command line.
 * cmd: Pointer to the command string.
 */
void handle_command(char *cmd) {
	if (!strcmp(cmd, "version")) {
		printf("versions are sent automatically now!!\n");
	}

	return;
}

/**
 * Helper function. Connects to a client and saves peer in data structure.
 * Then kicks off version exchange.
 * address: An array of length 4. Holds the 4 parts of an ip address in normal order.
 * port: TCP port of peer to connect to.
 */
void connect_client(uint8_t address[4], uint16_t port) {
	// Local variables.
	int sock;	// Socket holder.
	struct sockaddr_in addr;	// Address struct.
	CBPosition root;	// Root of data structure.
	// Peer variables.
	CBByteArray *ip;
	CBNetworkAddress *peerAddr;
	CBPeer *peer;

	// Create socket.
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error creating client socket");
		return;
	}

	// Setup address struct.
	memset(&addr, sizeof(addr), 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = (((((address[3] << 8) | address[2]) << 8) | address[1]) << 8) | address[0];

	// Connect to client.
	if (connect(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
		perror("Error connecting to client");
		return;
	}

	// Setup peer.
	ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, address[0], address[1], address[2], address[3]}, 16);
	peerAddr = CBNewNetworkAddress(0, ip, port, CB_SERVICE_FULL_BLOCKS, false);
	peer = CBNewPeerByTakingNetworkAddress(peerAddr);
	peer->socketID = sock;

	// Add peer to data structure.
	if (!CBAssociativeArrayGetLast(&peerSocks, &root)) {
		root.node = peerSocks.root;
		root.index = 0;
	}
	CBAssociativeArrayInsert(&peerSocks, peer, root, (CBBTreeNode *)NULL);

	// Kick off version exchange by sending our version.
	send_version(peer);
}

/**
 * Helper function. Sends version information to a client.
 * peer: The peer to send your version to.
 */
void send_version(CBPeer *peer) {
    // Setup source address (our own) information.
    CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
    CBByteArray *ua = CBNewByteArrayFromString("cmsc417versiona", '\00');
    CBNetworkAddress *sourceAddr = CBNewNetworkAddress(0, ip, 0, CB_SERVICE_FULL_BLOCKS, false);

    // Generate version info and message.
    int nonce = rand();
    CBVersion *version = CBNewVersion(VERSION, CB_SERVICE_FULL_BLOCKS, time(NULL), &peer->base, sourceAddr, nonce, ua, 0);
    CBMessage *message = CBGetMessage(version);

    // Setup header.
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

    // Send the header.
    send(peer->socketID, header, 24, 0);
    
    // Send the message.
    send(peer->socketID, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length, 0);

    // Set flag in peer object.
    peer->versionSent = true;

    // Release memory.
    // CBReleaseObject(ip);
    // CBReleaseObject(ua);
    // CBReleaseObject(sourceAddr);
    // CBFreeMessage(message);
    // CBReleaseObject(version);
}

/**
 * Helper function. Send a getaddr message to a peer.
 * peer: Peer to send a getaddr message to.
 */
void send_getaddr(CBPeer *peer) {
	// Setup header.
    char header[24];
    memcpy(header + CB_MESSAGE_HEADER_TYPE, "getaddr\0\0\0\0\0", 12);

    // Set netmagic and length.
    CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
    CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, 0);

    // Make checksum.
    uint8_t hash[32];
    uint8_t hash2[32];
    CBSha256((unsigned char *)"", 0, hash);
    CBSha256(hash, 32, hash2);
    memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, hash2, 4);

    // Send header.
    send(peer->socketID, header, 24, 0);

    peer->getAddresses = true;
}

/**
 * Send a message to get blocks from a peer.
 * peer: Peer to get blocks from.
 */
void send_getblocks(CBPeer *peer) {
	uint32_t message_len;

	// Setup header.
	char header[24];
	memcpy(header + CB_MESSAGE_HEADER_TYPE, "getblocks\0\0\0\0", 12);

	// Generate serialized data for message.
	CBMessage *message = CBGetMessage(&getBlocks);
	message_len = CBGetBlocksCalculateLength(&getBlocks);
	message->bytes = CBNewByteArrayOfSize(message_len);
	message_len = CBGetBlocksSerialise(&getBlocks, false);

	// Set netmagic and length.
	CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
	CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message_len);

	// Make checksum.
	uint8_t hash[32];
	uint8_t hash2[32];
	CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
	CBSha256(hash, 32, hash2);
	memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, hash2, 4);

	// Send header.
	send(peer->socketID, header, 24, 0);

	// Send message.
	send(peer->socketID, message->bytes->sharedData->data + message->bytes->offset, message->bytes->length, 0);
}

/**
 * Receive a message from a peer.
 * peer: peer to receive a message from.
 */
void receive_message(CBPeer *peer) {
	// Message local variables.
	char header[24];	// header data

	// Read message header from socket.
	recv(peer->socketID, header, 24, 0);
	if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
		printf("Wrong netmagic.\n");
		return;
	}

	// Read message payload.
	unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
	char *payload = (char *)malloc(length);
	int tread = 0;
	if (length) {
		while (tread < length) {
			tread += recv(peer->socketID, payload + tread, length, 0);
			// printf("%d of %d received\n", tread, length);
		}
	}

	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12)) {
		// If we received a version header.
		printf("received version header\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
		// If we received a verack, update the peer info to say we have finished
		// the version exchange.
		peer->versionAck = true;
		printf("received verack header\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "addr\0\0\0\0\0\0\0\0", 12)) {
		// We've received a addr. Parse the payload for peers.
		printf("received addr header\n");
		parse_addr((uint8_t *)payload);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "inv\0\0\0\0\0\0\0\0\0", 12)) {
		// We've received an inv header.
		printf("received inv header\n");
		parse_inv((uint8_t *)payload);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
		printf("received ping header\n");
	}

	free(payload);
}

/**
 * Parse an address list and add the addresses.
 * addr_list: Pointer to the memory location of the address list.
 */
void parse_addr(uint8_t *addr_list) {
	// Local variables.
	uint64_t j;	// Iterating uint64.
	uint8_t *data;	// Actual address data.

	// Decode the varint and get pointer to data.
	CBByteArray *bytes = CBNewByteArrayWithData(addr_list, 8);
	CBVarInt var_len = CBVarIntDecode(bytes, 0);
	data = addr_list + var_len.size;

	// Loop through address list elements.
	for (j = 0; j < var_len.val; j++) {
		// printf("loop %llu\n", j);
		// Check for private addresses.
		uint8_t firstoct = data[(j*30) + 24];
		uint8_t secondoct = data[(j*30) + 25];
		if (firstoct == 10) continue;
		else if (firstoct == 172 && secondoct >= 16 && secondoct <= 21) continue;
		else if (firstoct == 192 && secondoct == 168) continue;

		// printf("%hhu.%hhu.%hhu.%hhu:%hu\n", data[(j*30) + 24], data[(j*30) + 25], data[(j*30) + 26], data[(j*30) + 27], data[(j*30) + 28]);

		// Store address and port information.
		uint8_t address[4] = {firstoct, secondoct, data[(j*30) + 26], data[(j*30) + 27]};
		uint16_t port = data[(j*30) + 28];

		// Check data structure for address.
		CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, address[0], address[1], address[2], address[3]}, 16);
		CBNetworkAddress *peerAddr = CBNewNetworkAddress(0, ip, port, CB_SERVICE_FULL_BLOCKS, false);
		CBPeer *findpeer = CBNewPeerByTakingNetworkAddress(peerAddr);
		CBFindResult find = CBAssociativeArrayFind(&peerSocks, findpeer);

		// If client is not in data structure, connect to the client.
		if (!find.found) {
			// int32_t dt = data[(j*30)];
			// printf("connect new client %s", asctime(localtime(&dt)));
			// connect_client(address, port);
		}

		// CBFreeByteArray(ip);
		// CBFreeNetworkAddress(peerAddr);
		// CBReleaseObject(findpeer);
	}
}

void parse_inv(uint8_t *inv_list) {
	uint8_t *data;
	uint64_t i, new = 0;
	CBByteArray *getdatalist = NULL;

	CBByteArray *bytes = CBNewByteArrayWithData((uint8_t *)inv_list, 8);
	CBVarInt var_len = CBVarIntDecode(bytes, 0);
	data = inv_list + var_len.size;

	for (i = 0; i < var_len.val; i++) {
		if (data[i * 36] == CB_INVENTORY_ITEM_BLOCK && !CBBlockChainStorageBlockExists(&fullVal, data + (i * 36) + 4)) {
			if (!getdatalist) {
				getdatalist = CBNewByteArrayWithDataCopy(data[i * 36], 36);
			} else {
				CBByteArray *newlist = CBNewByteArrayOfSize((new + 1) * 36);
				CBByteArrayCopyByteArray(newlist, new * 36, getdatalist);
				CBByteArray *temp = getdatalist;
				getdatalist = newlist;
				CBFreeByteArray(temp);
			}
			new++;
		}
	}

	printf("new blocks %lld\n", new);
}
