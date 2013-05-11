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
#include <CBInventoryBroadcast.h>
#include <CBTransaction.h>
#include <CBTransactionInput.h>
#include <CBTransactionOutput.h>
#include <CBScript.h>
#include <CBObject.h>

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

// Global full validator and block chain storage variables.
CBFullValidator fullVal;
uint64_t bcStorage;
bool badBCS;

CBInventoryBroadcast *invbroad = NULL;

// Shared running variable.
bool running = true;

// Helper function definitions.
CBCompare compare_peers(void *key1, void *key2);
void *command_loop(void *arg);
void handle_command(char *cmd);
void connect_client(uint8_t address[4], uint16_t port);
bool send_message(CBPeer *peer, CBMessage *message);
bool queue_message(CBPeer *peer, CBMessage *message);
CBMessage *poll_queue(CBPeer *peer);
CBMessage *dequeue_message(CBPeer *peer);
void send_version(CBPeer *peer);
void send_getaddr(CBPeer *peer);
void send_getblocks(CBPeer *peer);
void send_getdata(CBPeer *peer);
void receive_message(CBPeer *peer);
void parse_addr(uint8_t *addr_list);
void parse_inv(uint8_t *inv_list);
void parse_block(uint8_t *blockdata);
CBTransaction *parse_tx(uint8_t *txdata, uint64_t *length);

/**
 * Main bitshekel client entry point.
 */
int main() {
	CBPosition iter; // associative array iteration placeholder
	pthread_t command_thread;	// handler to command loop thread

	// Initialize the associative array.
	if (!CBInitAssociativeArray(&peerSocks, compare_peers, NULL)) {
		printf("Error initializing associative array.\n");
	}

	// Setup full validator and block chain storage.
	remove("./bitshekel/blk_log.dat");
	remove("./bitshekel/blk_0.dat");
	remove("./bitshekel/blk_1.dat");
	remove("./bitshekel/blk_2.dat");
	bcStorage = CBNewBlockChainStorage("./bitshekel/");
	CBInitFullValidator(&fullVal, bcStorage, &badBCS, (CBFullValidatorFlags)NULL);

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
			CBPeer *peer = (CBPeer *)(iter.node->elements[iter.index]);
			int sock = peer->socketID;
			FD_SET(sock, &inSocks);
			FD_SET(sock, &outSocks);
			if (sock > max_desc) max_desc = sock;

			// Check if different messages need to be sent.
			if (!peer->versionSent) send_version(peer);
			else if (peer->versionAck) {
				if (!peer->getAddresses) send_getaddr(peer);
				if (!sendgetblocks) {
					sendgetblocks = true;
					send_getblocks(peer);
				} else if (invbroad) {
					send_getdata(peer);
				}
			}
		} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

		// Setup timeout timeval.
		struct timeval timeout;
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;

		// Call select.
		if (select(max_desc + 1, &inSocks, &outSocks, NULL, &timeout) != 0) {
			// Iterate through associative array elements and check if there is data to read or write.
			CBAssociativeArrayGetFirst(&peerSocks, &iter);
			do {
				CBPeer *peer = (CBPeer *)(iter.node->elements[iter.index]);
				int sock = peer->socketID;

				if (FD_ISSET(sock, &outSocks)) {
					while (peer->sendQueueSize) {
						CBMessage *message = dequeue_message(peer);
						if (!send_message(peer, message))
							printf("Send unsuccessful.\n");
						else
							CBFreeMessage(message);
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
	CBByteArray *peerip;
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
	peerip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, address[0], address[1], address[2], address[3]}, 16);
	peerAddr = CBNewNetworkAddress(0, peerip, port, CB_SERVICE_FULL_BLOCKS, false);
	peer = CBNewPeerByTakingNetworkAddress(peerAddr);
	peer->socketID = sock;

	// Add peer to data structure.
	if (!CBAssociativeArrayGetLast(&peerSocks, &root)) {
		root.node = peerSocks.root;
		root.index = 0;
	}
	CBAssociativeArrayInsert(&peerSocks, peer, root, (CBBTreeNode *)NULL);
}

/**
 * Queues a message onto a peers send queue.
 * peer: Peer to append message to.
 * message: Message to append.
 * returns: Whether queueing succeeded.
 */
bool queue_message(CBPeer *peer, CBMessage *message) {
	int newtail;

	// If the queue is full, return false.
	if (peer->sendQueueSize > CB_SEND_QUEUE_MAX_SIZE) return false;

	// Calculate the new tail position.
	newtail = peer->sendQueueFront + peer->sendQueueSize;
	// If the tail position is past the array end, wrap around.
	if (newtail >= CB_SEND_QUEUE_MAX_SIZE)
		newtail -= CB_SEND_QUEUE_MAX_SIZE;

	// Increase the current queue size.
	peer->sendQueueSize++;

	// Reference the message at the new tail.
	peer->sendQueue[newtail] = message;

	return true;
}

/**
 * Get a pointer to the current head of the queue.
 * peer: Peer to poll message from.
 * returns: Pointer to a message.
 */
CBMessage *poll_queue(CBPeer *peer) {
	return peer->sendQueue[peer->sendQueueFront];
}

/**
 * Dequeues a message from a peer send queue. Also returns a pointer
 * dequeued message.
 * peer: Peer to dequeue from.
 * returns: Pointer to a message.
 */
CBMessage *dequeue_message(CBPeer *peer) {
	// Get a pointer to the message to be dequeued.
	CBMessage *message = peer->sendQueue[peer->sendQueueFront];

	// Move the send queue head up. If we reach the end,
	// wrap around.
	peer->sendQueueFront++;
	if (peer->sendQueueFront >= CB_SEND_QUEUE_MAX_SIZE)
		peer->sendQueueFront = 0;

	// Update the queue size.
	peer->sendQueueSize--;

	return message;
}

/**
 * Helper function. Sends an arbitrary message to a peer.
 * peer: Pointer to the peer to send message to.
 * message: Pointer to the message to send.
 * returns: Whether the send was successful.
 */
bool send_message(CBPeer *peer, CBMessage *message) {
	char header[24];
	char mtype[12] = {0};
	uint8_t hash[24], hash2[24];

	if (!message->serialised) return false;

	// Setup header.
	switch (message->type) {
		case CB_MESSAGE_TYPE_VERSION:
			strcpy(mtype, "version"); break;
		case CB_MESSAGE_TYPE_GETADDR:
			strcpy(mtype, "getaddr"); break;
		case CB_MESSAGE_TYPE_GETBLOCKS:
			strcpy(mtype, "getblocks"); break;
		case CB_MESSAGE_TYPE_GETDATA:
			strcpy(mtype, "getdata"); break;
		default:
			return false;
	}
	memcpy(header + CB_MESSAGE_HEADER_TYPE, mtype, 12);

	// Setup netmagic and message length.
	CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
    CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);

    // Setup checksum.
    if (message->bytes->sharedData)
    	CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
   	else
   		CBSha256((unsigned char *)"", 0, hash);
    CBSha256(hash, 32, hash2);
    memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, hash2, 4);

    // Send the header.
    if (send(peer->socketID, header, 24, 0) != 24) return false;
    
    // Send the message.
    if (message->bytes->sharedData)
    	if (send(peer->socketID, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length, 0) != message->bytes->length)
    		return false;

    // Set peer flags.
    switch (message->type) {
		case CB_MESSAGE_TYPE_VERSION:
			peer->versionSent = true; break;
		case CB_MESSAGE_TYPE_GETADDR:
			peer->getAddresses = true; break;
		default: break;
	}

	return true;
}

/**
 * Constructs and sends a version message.
 * peer: Peer to send version message to.
 */
void send_version(CBPeer *peer) {
	CBByteArray *sip, *ua;
	CBNetworkAddress *sourceAddr;
	CBVersion *version;
	CBMessage *message, *qmessage;
	uint32_t len;
	int nonce;

	// Setup source address (our own) information.
    sip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
    ua = CBNewByteArrayFromString("cmsc417versiona", '\00');
    sourceAddr = CBNewNetworkAddress(0, sip, 0, CB_SERVICE_FULL_BLOCKS, false);

    // Generate version info and message.
    nonce = rand();
	version = CBNewVersion(VERSION, CB_SERVICE_FULL_BLOCKS, time(NULL), &peer->base, sourceAddr, nonce, ua, 0);
    message = CBGetMessage(version);

    // Serialize into message.
    len = CBVersionCalculateLength(version);
    message->bytes = CBNewByteArrayOfSize(len);
    len = CBVersionSerialise(version, false);

    // Copy into the final message object.
    qmessage = CBNewMessageByObject();
    CBInitMessageByData(qmessage, message->bytes);
    CBRetainObject(message->bytes);
    qmessage->type = CB_MESSAGE_TYPE_VERSION;

	// Kick off version exchange by sending our version.
	queue_message(peer, qmessage);

	// Cleanup memory.
	CBFreeVersion(version);
	CBFreeNetworkAddress(sourceAddr);
	CBFreeByteArray(ua);
	CBFreeByteArray(sip);
}

/**
 * Constructs and sends a getaddr message.
 * peer: Peer to send getaddr message to.
 */
void send_getaddr(CBPeer *peer) {
	CBMessage *message = CBNewMessageByObject();

	// Setup message details.
	message->type = CB_MESSAGE_TYPE_GETADDR;
	message->bytes = CBNewByteArrayOfSize(0);
	message->serialised = true;

	// Queue message.
	queue_message(peer, message);
}

/**
 * Vonstructs and sends a getblocks message.
 * peer: Peer to send getblocks message to.
 */
void send_getblocks(CBPeer *peer) {
	uint32_t message_len;
	CBByteArray *hashStop;
	CBGetBlocks getBlocks;
	CBChainDescriptor chainDesc;
	CBBlock *initBlock;
	uint8_t initBlockHash[32];
	CBByteArray *initBlockHashByteArray;
	CBMessage *message, *qmessage;

	// Initialize chain desc and get blocks.
	if (!CBInitChainDescriptor(&chainDesc)) {
		printf("Error initializing chain descriptor.\n");
	}
	hashStop = CBNewByteArrayOfSize(4);
	CBByteArraySetInt32(hashStop, 0, 0);
	if (!CBInitGetBlocks(&getBlocks, VERSION, &chainDesc, hashStop)) {
		printf("Error initializing get blocks.\n");
	}

	// Get genesis block, calculate hash, add to chain descriptor.
	initBlock = CBNewBlock();
	CBInitBlockGenesisUMDNet(initBlock);
	CBBlockCalculateHash(initBlock, initBlockHash);
	initBlockHashByteArray = CBNewByteArrayWithDataCopy(initBlockHash, 32);
	CBChainDescriptorAddHash(&chainDesc, initBlockHashByteArray);

	// Generate serialized data for message.
	message = CBGetMessage(&getBlocks);
	message_len = CBGetBlocksCalculateLength(&getBlocks);
	message->bytes = CBNewByteArrayOfSize(message_len);
	message_len = CBGetBlocksSerialise(&getBlocks, false);

	// Copy message into a message that won't be freed.
	qmessage = CBNewMessageByObject();
	qmessage->type = CB_MESSAGE_TYPE_GETBLOCKS;
	CBInitMessageByData(qmessage, message->bytes);
	CBRetainObject(message->bytes);

	queue_message(peer, qmessage);

	// Cleanup memory
	CBFreeByteArray(hashStop);
}

/**
 * Send a getdata message to a peer.
 * peer: Peer to get data from.
 */
void send_getdata(CBPeer *peer) {
	uint32_t message_len;
	CBMessage *message, *qmessage;

	// Generate serialized data for message.
	message = CBGetMessage(invbroad);
	message_len = CBInventoryBroadcastCalculateLength(invbroad);
	message->bytes = CBNewByteArrayOfSize(message_len);
	message_len = CBInventoryBroadcastSerialise(invbroad, false);

	// Copy message into a message that won't be freed.
	qmessage = CBNewMessageByObject();
	qmessage->type = CB_MESSAGE_TYPE_GETDATA;
	CBInitMessageByData(qmessage, message->bytes);
	CBRetainObject(message->bytes);

	queue_message(peer, qmessage);

	// Cleanup memory.
	CBFreeInventoryBroadcast(invbroad);
	invbroad = NULL;
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
			tread += recv(peer->socketID, payload + tread, length - tread, 0);
		}
	}

	printf("received %d byte ", tread);

	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12)) {
		// If we received a version header.
		printf("version header\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
		// If we received a verack, update the peer info to say we have finished
		// the version exchange.
		peer->versionAck = true;
		printf("verack header\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "addr\0\0\0\0\0\0\0\0", 12)) {
		// We've received a addr. Parse the payload for peers.
		printf("addr header\n");
		parse_addr((uint8_t *)payload);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "inv\0\0\0\0\0\0\0\0\0", 12)) {
		// We've received an inv header. Parse the payload for inventory.
		printf("inv header\n");
		parse_inv((uint8_t *)payload);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "block\0\0\0\0\0\0\0", 12)) {
		// We've received a block header. Parse it into a block and process.
		printf("block header\n");
		parse_block((uint8_t *)payload);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "tx\0\0\0\0\0\0\0\0\0\0", 12)) {
		printf("tx header\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
		printf("ping header\n");
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
		findpeer->socketID = -1;
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

/**
 * Parse an inventory list. For right now, it assumes it's a block list.
 * inv_list: The raw bytes of the inventory list.
 */
void parse_inv(uint8_t *inv_list) {
	uint8_t *data;
	uint64_t i, new = 0;
	CBByteArray *invhash, *bytes;
	CBInventoryItem **invitems;
	CBVarInt var_len;

	bytes = CBNewByteArrayWithDataCopy((uint8_t *)inv_list, 8);
	var_len = CBVarIntDecode(bytes, 0);
	data = inv_list + var_len.size;

	invitems = malloc(var_len.val * sizeof(CBInventoryItem *));

	for (i = 0; i < var_len.val; i++) {
		if (data[i * 36] == CB_INVENTORY_ITEM_BLOCK && !CBBlockChainStorageBlockExists(&fullVal, data + (i * 36) + 4)) {
			invhash = CBNewByteArrayWithDataCopy(data + (i * 36) + 4, 32);
			invitems[new] = CBNewInventoryItem((CBInventoryItemType)(data[i * 36]), invhash);
			new++;
		}
	}

	invitems = realloc(invitems, new * sizeof(CBInventoryItem *));

	invbroad = CBNewInventoryBroadcast();
	invbroad->itemNum = new;
	invbroad->items = invitems;
}

void parse_block(uint8_t *blockdata) {
	uint8_t hash[32];
	uint8_t hash2[32];
	CBByteArray *txbytes;
	CBBlock *block;
	CBVarInt tx_len;
	uint64_t i, tx_curr_size = 0, txsize;
	CBTransaction **transactions;
	time_t nettime;

	nettime = time(NULL);

	CBSha256(blockdata, 80, hash);
	CBSha256(hash, 32, hash2);
	
	txbytes = CBNewByteArrayWithData((uint8_t *)(blockdata + 80), 8);
	tx_len = CBVarIntDecode(txbytes, 0);

	block = CBNewBlock();
	memcpy(block->hash, hash2, 32);
	block->hashSet = true;
	block->version = blockdata[0];
	block->prevBlockHash = CBNewByteArrayWithDataCopy(blockdata + 4, 32);
	block->merkleRoot = CBNewByteArrayWithDataCopy(blockdata + 36, 32);
	block->time = blockdata[68];
	block->target = blockdata[72];
	block->nonce = blockdata[76];
	block->transactionNum = tx_len.val;

	transactions = malloc(tx_len.val * sizeof(CBTransaction *));
	for (i = 0; i < tx_len.val; i++) {
		transactions[i] = parse_tx(blockdata + 80 + tx_len.size + tx_curr_size, &txsize);
		tx_curr_size += txsize;
	}

	CBBlockStatus stat = CBFullValidatorProcessBlock(&fullVal, block, nettime);
	if (stat != CB_BLOCK_STATUS_BAD) printf("block status %d\n", stat);
}

/**
 * Parses a transaction memory block.
 * txdata: Raw byte data of transaction.
 * length: A length variable to set as the size of this transaction.
 * returns: Pointer to a CBTransaction.
 */
CBTransaction *parse_tx(uint8_t *txdata, uint64_t *length) {
	CBVarInt in_var, out_var, s_var;
	CBByteArray *invbytes, *outvbytes, *sbytes, *prevOutHash;
	uint64_t i, insize = 0, outsize = 0, totalsize = 0;
	uint8_t *indata, *outdata;
	CBTransactionInput **inputs;
	CBScript *script;
	CBTransactionOutput **outputs;
	CBTransaction *tx;

	// Calculate varint for inputs.
	invbytes = CBNewByteArrayWithData((uint8_t *)(txdata + 4), 8);
	in_var = CBVarIntDecode(invbytes, 0);
	indata = txdata + 4 + in_var.size;
	totalsize += 4 + in_var.size;

	inputs = malloc(in_var.val * sizeof(CBTransactionInput *));
	for (i = 0; i < in_var.val; i++) {
		sbytes = CBNewByteArrayWithData(indata + insize + 36, 8);
		s_var = CBVarIntDecode(sbytes, 0);

		script = CBNewScriptWithDataCopy(indata + insize + 36 + s_var.size, s_var.val);
		prevOutHash = CBNewByteArrayWithDataCopy(indata + insize, 32);

		inputs[i] = CBNewTransactionInput(script, indata[insize + 36 + s_var.size + s_var.val], prevOutHash, indata[insize + 32]);
		insize += 36 + s_var.size + s_var.val + 4;
	}
	totalsize += insize;

	outvbytes = CBNewByteArrayWithData((uint8_t *)(indata + insize), 8);
	out_var = CBVarIntDecode(outvbytes, 0);
	outdata = indata + insize + out_var.size;
	totalsize += out_var.size;

	outputs = malloc(out_var.val * sizeof(CBTransactionOutput *));
	for (i = 0; i < out_var.val; i++) {
		sbytes = CBNewByteArrayWithData(outdata + outsize + 8, 8);
		s_var = CBVarIntDecode(sbytes, 0);

		script = CBNewScriptWithDataCopy(outdata + outsize + 8 + s_var.size, s_var.val);

		outputs[i] = CBNewTransactionOutput(outdata[outsize], script);
		outsize += 8 + s_var.size + s_var.val;
	}
	totalsize += outsize + 4;

	tx = CBNewTransaction(outdata[outsize], txdata[0]);

	*length = totalsize;

	return tx;
}
