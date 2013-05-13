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

// Kale address array.
#define KALE 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25

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

// Shared inventory broadcast object. Will be filled when there is inventory to broadcast.
CBInventoryBroadcast *invbroad = NULL;
int lastGetData = 0;
bool uptodate = false, getblockssent = false;

// Shared running variable.
bool running = true;

// Helper function definitions.
static void print_hex(CBByteArray *str);
CBCompare compare_peers(void *key1, void *key2);
void *command_loop(void *arg);
void handle_command(char *cmd);
void connect_client(CBNetworkAddress *addr);
bool send_message(CBPeer *peer, CBMessage *message);
bool queue_message(CBPeer *peer, CBMessage *message);
CBMessage *poll_queue(CBPeer *peer);
CBMessage *dequeue_message(CBPeer *peer);
void send_version(CBPeer *peer);
void send_verack(CBPeer *peer);
void send_ping(CBPeer *peer);
void send_pong(CBPeer *peer);
void send_getaddr(CBPeer *peer);
void send_getblocks(CBPeer *peer);
void send_getdata(CBPeer *peer);
void receive_message(CBPeer *peer);
void parse_addr(uint8_t *addrlistdata);
void parse_inv(uint8_t *invdata, unsigned int length);
void parse_block(uint8_t *blockdata, unsigned int block);
void parse_tx(uint8_t *txdata, unsigned int length);

/**
 * Main bitshekel client entry point.
 */
int main() {
	CBPosition iter;
	pthread_t command_thread;
	uint8_t kaleIPArr[] = {KALE};
	CBByteArray *kaleIP;
	CBNetworkAddress *kaleAddr;
	int max_desc, sock;
	fd_set inSocks, outSocks;
	CBPeer *peer;
	struct timeval timeout, leftover;

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
	CBInitFullValidator(&fullVal, bcStorage, &badBCS, 0);

	// Setup the initial connection.
	kaleIP = CBNewByteArrayWithDataCopy(kaleIPArr, 16);
	kaleAddr = CBNewNetworkAddress(0, kaleIP, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
	connect_client(kaleAddr);

	// max file descriptor number
	max_desc = -1;

	// Create command loop thread.
	if (pthread_create(&command_thread, NULL, command_loop, NULL)) {
		printf("Error creating command thread.\n");
		return -1;
	}

	// Setup timeout timeval.
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;

	// Loop while client is running.
	while (running) {
		// Zero socket sets.
		FD_ZERO(&inSocks);
		FD_ZERO(&outSocks);

		// Iterate through associative array elements and add sockets to socket set.
		CBAssociativeArrayGetFirst(&peerSocks, &iter);
		do {
			peer = (CBPeer *)(iter.node->elements[iter.index]);
			sock = peer->socketID;
			FD_SET(sock, &inSocks);
			FD_SET(sock, &outSocks);
			if (sock > max_desc) max_desc = sock;

			// Check if different messages need to be sent.
			if (!peer->versionSent) send_version(peer);
			else if (peer->versionAck) {
				if (!peer->getAddresses) send_getaddr(peer);
				if (!uptodate && !lastGetData && !getblockssent) {
					send_getblocks(peer);
					getblockssent = true;
				} else if (invbroad) {
					send_getdata(peer);
				}
			}
		} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

		// Call select.
		if (select(max_desc + 1, &inSocks, &outSocks, NULL, &timeout) != 0) {
			// Iterate through associative array elements and check if there is data to read or write.
			CBAssociativeArrayGetFirst(&peerSocks, &iter);
			do {
				peer = (CBPeer *)(iter.node->elements[iter.index]);
				sock = peer->socketID;

				if (FD_ISSET(sock, &outSocks)) {
					while (peer->sendQueueSize) {
						CBMessage *message = dequeue_message(peer);
						if (!send_message(peer, message))
							printf("Send unsuccessful.\n");
						else
							CBReleaseObject(message);
					}
				}

				if (FD_ISSET(sock, &inSocks)) {
					receive_message(peer);
				}
			} while (!CBAssociativeArrayIterate(&peerSocks, &iter));
		} else {
			// Reset timeout.
			timeout.tv_sec = 60;
			timeout.tv_usec = 0;

			printf("timeout\n");
		}
	}

	// Join command loop thread.
	if (pthread_join(command_thread, NULL)) {
		printf("Error joining threads.\n");
		return -1;
	}

	// Loop through and close sockets/cleanup memory.
	CBAssociativeArrayGetFirst(&peerSocks, &iter);
	do {
		peer = (CBPeer *)(iter.node->elements[iter.index]);
		close(peer->socketID);
		CBReleaseObject(peer);
	} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

	// Cleanup memory.
	CBReleaseObject(&peerSocks);
	CBReleaseObject(kaleAddr);

	return 0;
}

/**
 * Helper function. Prints out hex.
 */
static void print_hex(CBByteArray *str) {
	int i = 0;
	uint8_t *ptr = str->sharedData->data;
	for (; i < str->length; i++) printf("%02x", ptr[str->offset + i]);
	printf("\n");
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

	// Compare the addresses.
	if (CBNetworkAddressEquals(&(peer1->base), &(peer2->base))) return CB_COMPARE_EQUAL;
	else return -1;
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
	// Exit requested.
	if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit")) { running = false; return; }

	printf("Command not recognized!\n");
}

/**
 * Helper function. Connects to a client and saves peer in data structure.
 * Then kicks off version exchange.
 * address: An array of length 4. Holds the 4 parts of an ip address in normal order.
 * port: TCP port of peer to connect to.
 */
void connect_client(CBNetworkAddress *netAddr) {
	int sock;
	struct sockaddr_in addr;
	CBPosition root;
	CBPeer *peer;

	// Create socket.
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error creating client socket");
		return;
	}

	// Setup address struct.
	memset(&addr, sizeof(addr), 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(netAddr->port);
	addr.sin_addr.s_addr = CBByteArrayReadInt32(netAddr->ip, 12);

	// Connect to client.
	if (connect(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
		perror("Error connecting to client");
		return;
	}

	// Setup peer.
	peer = CBNewPeerByTakingNetworkAddress(netAddr);
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
	CBReleaseObject(version);
	CBReleaseObject(sourceAddr);
	CBReleaseObject(ua);
	CBReleaseObject(sip);
}

/**
 * Constructs and sends a verack message.
 * peer: Peer to send verack message to.
 */
void send_verack(CBPeer *peer) {
	CBMessage *message = CBNewMessageByObject();

	// Setup message details.
	message->type = CB_MESSAGE_TYPE_VERACK;
	message->bytes = CBNewByteArrayOfSize(0);
	message->serialised = true;

	queue_message(peer, message);
}

/**
 * Constructs and sends a ping message.
 * peer: Peer to send ping message to.
 */
void send_ping(CBPeer *peer) {
	CBMessage *message = CBNewMessageByObject();

	// Setup message details.
	message->type = CB_MESSAGE_TYPE_PING;
	message->bytes = CBNewByteArrayOfSize(0);
	message->serialised = true;

	queue_message(peer, message);
}

/**
 * Constructs and sends a pong message.
 * peer: Peer to send pong message to.
 */
void send_pong(CBPeer *peer) {
	CBMessage *message = CBNewMessageByObject();

	// Setup message details.
	message->type = CB_MESSAGE_TYPE_PONG;
	message->bytes = CBNewByteArrayOfSize(0);
	message->serialised = true;

	queue_message(peer, message);
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

	queue_message(peer, message);
}

/**
 * Vonstructs and sends a getblocks message.
 * peer: Peer to send getblocks message to.
 */
void send_getblocks(CBPeer *peer) {
	uint32_t message_len;
	CBGetBlocks getBlocks;
	CBChainDescriptor chainDesc;
	CBBlock *block;
	CBByteArray *blockHash, *hashStop;
	CBMessage *message, *qmessage;
	bool building = true;
	int step = 1, index = 0, next = 0, branchNum, branchIndex;

	// Initialize chain descriptor.
	if (!CBInitChainDescriptor(&chainDesc)) {
		printf("Error initializing chain descriptor.\n");
	}

	// Setup branch vars to point to head of main branch.
	branchNum = fullVal.mainBranch;
	branchIndex = fullVal.branches[branchNum].numBlocks - 1;
	
	// Loop and build chain descriptor.
	while (building) {
		// Load block from storage.
		block = CBBlockChainStorageLoadBlock(&fullVal, branchIndex, branchNum);
		if (!block) return;

		// Setup branch index/number for next loop.
		branchIndex--;
		if (branchIndex < 0) {
			// If we are past index 0 of branch, check parent branch.
			// If parent branch matches current branch, we are at the end.
			if (fullVal.branches[branchNum].parentBranch == branchNum)
				building = false;
			branchIndex = fullVal.branches[branchNum].parentBlockIndex;
			branchNum = fullVal.branches[branchNum].parentBranch;
		}

		// If we are at the next hash to add...
		if (index == next) {
			// Increase step if index is above 10.
			if (index >= 10) step *= 2;
			// Set next hash index.
			next += step;
			// Get hash and add.
			blockHash = CBNewByteArrayWithDataCopy(CBBlockGetHash(block), 32);
			if (index == 0) hashStop = blockHash;
			CBChainDescriptorAddHash(&chainDesc, blockHash);
		}
		index++;

		// Cleanup memory.
		CBReleaseObject(block);
	}

	// Initialize get blocks.
	if (!CBInitGetBlocks(&getBlocks, VERSION, &chainDesc, hashStop)) {
		printf("Error initializing get blocks.\n");
	}

	printf("hashes sent: %d\n", chainDesc.hashNum);

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
	CBReleaseObject(hashStop);
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
	CBReleaseObject(invbroad);
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

	// printf("received %d byte ", tread);

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
		parse_inv((uint8_t *)payload, tread);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "block\0\0\0\0\0\0\0", 12)) {
		// We've received a block header. Parse it into a block and process.
		// printf("block header\n");
		parse_block((uint8_t *)payload, tread);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "tx\0\0\0\0\0\0\0\0\0\0", 12)) {
		printf("tx header\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
		printf("ping header\n");
		send_pong(peer);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "pong\0\0\0\0\0\0\0\0", 12)) {
		printf("pong header\n");
	}

	// Free payload.
	free(payload);
}

/**
 * Parse an address list and add the addresses.
 * addrlistdata: Pointer to the memory location of the address list.
 */
void parse_addr(uint8_t *addrlistdata) {
	// Local variables.
	uint64_t j;	// Iterating uint64.
	uint8_t *data;	// Actual address data.

	// Decode the varint and get pointer to data.
	CBByteArray *bytes = CBNewByteArrayWithData(addrlistdata, 8);
	CBVarInt var_len = CBVarIntDecode(bytes, 0);
	data = addrlistdata + var_len.size;

	// Loop through address list elements.
	for (j = 0; j < var_len.val; j++) {
		// Copy raw bytes and deserialize.
		CBByteArray *addrdata = CBNewByteArrayWithDataCopy(data + (j * 30), 30);
		CBNetworkAddress *addr = CBNewNetworkAddressFromData(addrdata, true);
		CBNetworkAddressDeserialise(addr, true);

		// Create peer and check data structure.
		CBPeer *findpeer = CBNewPeerByTakingNetworkAddress(addr);
		CBFindResult find = CBAssociativeArrayFind(&peerSocks, findpeer);

		// If client is not in data structure, connect to the client.
		if (!find.found) {
			// connect_client(findpeer);
		}
	}
}

/**
 * Parse an inventory list. For right now, it assumes it's a block list.
 * invdata: The raw bytes of the inventory list.
 * length: Length of the raw bytes.
 */
void parse_inv(uint8_t *invdata, unsigned int length) {
	CBByteArray *invbroadba;

	// Copy raw bytes and deserialise.
	invbroadba = CBNewByteArrayWithDataCopy(invdata, length);
	invbroad = CBNewInventoryBroadcastFromData(invbroadba);
	CBInventoryBroadcastDeserialise(invbroad);

	// If we receive no inventory items, we are up to date.
	if (!invbroad->itemNum) uptodate = true;
	else if(invbroad->itemNum && uptodate) uptodate = false;

	// We've received the response to getblocks, set flag.
	lastGetData = invbroad->itemNum;
	getblockssent = false;

	printf("items received: %d\n", invbroad->itemNum);
}

/**
 * Parse a block.
 * blockdata: Raw byte data of block.
 * length: Length of the raw bytes.
 */
void parse_block(uint8_t *blockdata, unsigned int length) {
	CBByteArray *blockba;
	CBBlock *block;

	// Copy raw bytes and deserialise.
	blockba = CBNewByteArrayWithDataCopy(blockdata, length);
	block = CBNewBlockFromData(blockba);
	CBBlockDeserialise(block, true);

	// Process the block.
	CBFullValidatorProcessBlock(&fullVal, block, time(NULL));

	// Reduce count of get data request.
	lastGetData--;

	// Cleanup memory.
	CBReleaseObject(block);
	CBReleaseObject(blockba);
}

/**
 * Parses a transaction.
 * txdata: Raw byte data of transaction.
 * length: Length of the raw bytes.
 */
void parse_tx(uint8_t *txdata, unsigned int length) {
	CBByteArray *txba;
	CBTransaction *tx;

	// Copy raw bytes and deserialise.
	txba = CBNewByteArrayWithDataCopy(txdata, length);
	tx = CBNewTransactionFromData(txba);
	CBTransactionDeserialise(tx);
}
