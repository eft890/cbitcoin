// Include standard libraries.
#include <netinet/in.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>

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
#include <CBAddress.h>

// Client version.
#define VERSION 70001

// Default satoshi port.
#define DEFAULT_PORT 28333

// Netmagic to add to message headers.
#define NETMAGIC 0xd0b4bef9		// umdnet netmagic

// Kale address array.
#define KALE 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25

// Bitcoin address
#define BC_ADDRESS "1FkeuZQZoAJXxRTYN7sWaUJdyagFdBZFBT"
#define BC_ADDRESS_LEN 34

// Public key
#define PUBLIC_KEY 0x04, 0x8D, 0x46, 0x4B, 0xA0, 0xB7, 0x07, 0xE9, 0x32, 0xEC, 0xE4, 0x7C, 0x26, 0xC8, 0x44, 0x7D, 0xBC, 0xFF, 0x7D, 0x75, 0x97, 0x6F, 0x3A, 0x2F, 0x60, 0xDF, 0x0D, 0x30, 0xC3, 0x9E, 0x1F, 0x8A, 0x0B, 0x99, 0x32, 0xDC, 0x81, 0x2E, 0x07, 0x95, 0x20, 0xEB, 0xF0, 0xCA, 0xF3, 0x3D, 0x10, 0xB1, 0x94, 0x25, 0x1F, 0xC0, 0xFF, 0xCF, 0xE3, 0x47, 0x10, 0xB2, 0x9D, 0x8D, 0x75, 0x40, 0x31, 0x9A, 0xF3
#define PUBLIC_KEY_LEN 65

// Private key
#define PRIVATE_KEY 0xC4, 0xFD, 0x76, 0xA9, 0x4A, 0x1B, 0x79, 0xEC, 0x1B, 0x41, 0xB0, 0x5A, 0x03, 0xC6, 0x12, 0xEF, 0x3E, 0x68, 0xFA, 0x32, 0xDB, 0x7F, 0x9C, 0x53, 0x6F, 0x2C, 0x5B, 0xCF, 0x01, 0x6A, 0xC9, 0xA4
#define PRIVATE_KEY_LEN 32

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
CBFullValidator *fullVal;
uint64_t bcStorage;
bool badBCS;

// Shared inventory broadcast object. Will be filled when there is inventory to broadcast.
CBInventoryBroadcast *invbroad = NULL;
CBInventoryItemType invtype;
int lastGetData = 0;
bool uptodate = false, getblockssent = false;
int numWaiting = 0;

// Byte array that holds the hash of our public key for comparison.
CBByteArray *publicAddr;

// Public/private key arrays.
uint8_t publicKey[PUBLIC_KEY_LEN] = {PUBLIC_KEY};
uint8_t privateKey[PRIVATE_KEY_LEN] = {PRIVATE_KEY};

// Custom struct for unspent outputs.
typedef struct {
	CBByteArray *txHash;
	uint32_t outputIndex;
	uint64_t amount;
} UnspentOutput;

// List of hashes for transactions in which we have spendable coins.
unsigned int numOwned = 0, ownedStart = 0, numKnownTx = 0;
UnspentOutput *ownedOutputs = NULL;
CBTransaction **txs;

// Shared running variable.
bool running = true;

// Global debug logging variables.
bool debug = false, show_blocks = false, show_timeouts = false, show_rcv = false;


// Helper function definitions.
static void print_hex(CBByteArray *str);
CBCompare compare_peers(void *key1, void *key2);
void rl_handler(char *line);
void handle_command(char *line);
uint64_t calculate_owned_coins();
void send_coins(uint64_t* spendAmounts, char **addresses, int numSpends);
bool verify_tx(CBTransaction* tx);
void connect_client(CBNetworkAddress *addr);
bool send_message(CBPeer *peer, CBMessage *message);
bool queue_message(CBPeer *peer, CBMessage *message);
CBMessage *poll_queue(CBPeer *peer);
CBMessage *dequeue_message(CBPeer *peer);
void send_version(CBPeer *peer);
void send_verack(CBPeer *peer);
void send_ping(CBPeer *peer);
void send_pong(CBPeer *peer, int nonce);
void send_getaddr(CBPeer *peer);
void send_getblocks(CBPeer *peer);
void send_getdata(CBPeer *peer);
void send_inv(CBPeer *peer);
void send_tx(CBPeer *peer, uint8_t *hash);
void receive_message(CBPeer *peer);
void parse_addr(uint8_t *addrlistdata);
void parse_inv(uint8_t *invdata, unsigned int length);
void parse_getdata(uint8_t *gddata, unsigned int length, CBPeer *peer);
void parse_block(uint8_t *blockdata, unsigned int block);
void parse_tx(uint8_t *txdata, unsigned int length);

/**
 * Main bitshekel client entry point.
 */
int main(int argc, char *argv[]) {
	CBPosition iter;
	uint8_t kaleIPArr[] = {KALE};
	CBByteArray *kaleIP, *bc_addressba;
	CBNetworkAddress *kaleAddr;
	int max_desc, sock, num_timeout;
	fd_set inSocks;
	CBPeer *peer;
	CBMessage *message;
	struct timeval timeout;
	CBAddress *bc_address;

	// Check for debug output argument.
	if (argc > 1) {
		for (max_desc = 0; max_desc < argc; max_desc++) {
			if (!strcmp(argv[max_desc], "-d")) debug = true;
			if (!strcmp(argv[max_desc], "-b")) show_blocks = true;
			if (!strcmp(argv[max_desc], "-t")) show_timeouts = true;
			if (!strcmp(argv[max_desc], "-r")) show_rcv = true;
		}
	}

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
	fullVal = CBNewFullValidator(bcStorage, &badBCS, 0);

	// Setup the initial connection.
	kaleIP = CBNewByteArrayWithDataCopy(kaleIPArr, 16);
	kaleAddr = CBNewNetworkAddress(0, kaleIP, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
	connect_client(kaleAddr);

	// Create our bitcoin address.
	bc_addressba = CBNewByteArrayWithDataCopy((uint8_t *)BC_ADDRESS, BC_ADDRESS_LEN);
	bc_address = CBNewAddressFromString(bc_addressba, false);
	publicAddr = CBByteArraySubReference(CBGetByteArray(bc_address), 1, 20);

	// max file descriptor number
	max_desc = -1;

	// Setup timeout timeval.
	timeout.tv_sec = 0;
	timeout.tv_usec = 500;
	num_timeout = 0;

	printf("Please wait while the client updates the block chain...\n");

	// Install readline handler.
	rl_callback_handler_install("Enter command > ", (rl_vcpfunc_t *)&rl_handler);

	// Loop while client is running.
	while (running) {
		// Zero socket sets.
		FD_ZERO(&inSocks);

		// Setup stdin file descriptor.
		FD_SET(STDIN_FILENO, &inSocks);

		// Iterate through associative array elements and add sockets to socket set.
		CBAssociativeArrayGetFirst(&peerSocks, &iter);
		do {
			peer = (CBPeer *)(iter.node->elements[iter.index]);
			sock = peer->socketID;
			FD_SET(sock, &inSocks);
			if (sock > max_desc) max_desc = sock;

			// Check if different messages need to be sent.
			if (!peer->versionSent) send_version(peer);
			else if (peer->versionAck) {
				if (!peer->getAddresses) send_getaddr(peer);
				if (!uptodate && !lastGetData && !getblockssent) {
					send_getblocks(peer);
					numWaiting = 0;
					getblockssent = true;
				}
				if (invbroad) {
					if (invtype == CB_INVENTORY_ITEM_BLOCK) send_getdata(peer);
					else if (invtype == CB_INVENTORY_ITEM_TRANSACTION) send_inv(peer);
				}
			}
		} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

		// Call select.
		if (select(max_desc + 1, &inSocks, NULL, NULL, &timeout) != 0) {
			// Iterate through associative array elements and check if there is data to read or write.
			CBAssociativeArrayGetFirst(&peerSocks, &iter);
			do {
				peer = (CBPeer *)(iter.node->elements[iter.index]);
				sock = peer->socketID;

				if (FD_ISSET(sock, &inSocks)) {
					receive_message(peer);
				}
			} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

			// Check stdin and call readline to read char.
			if (FD_ISSET(STDIN_FILENO, &inSocks)) {
				rl_callback_read_char();
			}
		} else {
			// Check if we are up to date.
			if (getblockssent) {
				numWaiting++;
				if (numWaiting > 1) {
					getblockssent = false;
					uptodate = true;
					printf("Up to date.\n");
				}
			}

			// Reset timeout.
			timeout.tv_sec = 2;
			timeout.tv_usec = 0;
			if (debug && show_timeouts) printf("timeout\n");

			// Update timeout counter.
			num_timeout++;
			if (num_timeout == 20) {
				// Reached 60 seconds, send ping.
				CBAssociativeArrayGetFirst(&peerSocks, &iter);
				do {
					send_ping((CBPeer *)(iter.node->elements[iter.index]));
				} while (!CBAssociativeArrayIterate(&peerSocks, &iter));
				num_timeout = 0;
			}

			// Loop through peers and send messages.
			CBAssociativeArrayGetFirst(&peerSocks, &iter);
			do {
				// While there are still messages, send them.
				while (peer->sendQueueSize) {
					peer = (CBPeer *)(iter.node->elements[iter.index]);
					message = dequeue_message(peer);
					if (!send_message(peer, message)) {
						if (debug) printf("Send unsuccessful.\n");
					} else {
						CBReleaseObject(message);
					}
				}
			} while (!CBAssociativeArrayIterate(&peerSocks, &iter));
		}
	}

	// Uninstall readline handler.
	rl_callback_handler_remove();

	// Loop through and close sockets/cleanup memory.
	CBAssociativeArrayGetFirst(&peerSocks, &iter);
	do {
		peer = (CBPeer *)(iter.node->elements[iter.index]);

		// Remove pending messages.
		while (peer->sendQueueSize) {
			message = dequeue_message(peer);
			CBReleaseObject(message);
		}

		close(peer->socketID);
		// CBFreeNetworkAddress(CBGetNetworkAddress(peer));
	} while (!CBAssociativeArrayIterate(&peerSocks, &iter));

	// Cleanup memory.
	CBReleaseObject(&peerSocks);
	CBReleaseObject(fullVal);
	CBFreeBlockChainStorage(bcStorage);

	CBReleaseObject(kaleIP);

	CBReleaseObject(publicAddr);
	CBReleaseObject(bc_address);
	CBReleaseObject(bc_addressba);

	if (invbroad) CBReleaseObject(invbroad);

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
 * Readline line handler.
 * line: Line sent in by call to line handler.
 */
void rl_handler(char *line) {
	// If the line is empty, free and continue loop.
	if (!line || !*line) {
		free(line);
		return;
	}

	// Add the line to history.
	add_history(line);

	// Pass the command to the command helper.
	handle_command(line);

	// Free line.
	free(line);
}

/**
 * Helper function. Handles commands from command line.
 * line: Pointer to the command string.
 */
void handle_command(char *line) {
	char delim[] = " ";
	char *command = NULL, **args = NULL, *temp = NULL, **addrs = NULL, *tempamt = NULL;
	int count = 0, i;
	uint64_t *amts = NULL, tamt = 0;
	bool cmdGood = true;

	// Loop through and receive all arguments.
	temp = strtok(line, delim);
	while (temp) {
		if (count == 0) command = temp;
		else {
			args = realloc(args, sizeof(char *) * count);
			args[count - 1] = temp;
		}
		temp = strtok(NULL, delim);
		count++;
	}

	// If token was not found, we have a no arg command.
	if (!temp && !count) command = line;

	// Exit requested.
	if (!strcmp(command, "exit") || !strcmp(command, "quit")) {
		running = false;

	// Help requested.
	} else if (!strcmp(command, "help")) {
		printf("Commands\n");
		printf("========\n");
		printf("quit, exit:\t\t\t\t\t\texit the client.\n");
		printf("status:\t\t\t\t\t\t\tshow unspent coins.\n");
		printf("send <amount> <address> ... <amount> <address>:\tsend <amounts> bitcoins to <addreses>.\n");
		printf("\t\t\t\t\t\t'200' would be decimals, '200.0' would be full coins\n");;
		printf("\n\nDebugging Commands\n");
		printf("================\n");
		printf("show <debug/sizes/blocks/timeouts>:\t\t\tShow various debugging outputs.\n");
		printf("hide <debug/sizes/blocks/timeouts>:\t\t\tHide various debugging outputs.\n");

	// Check coin status.
	} else if (!strcmp(command, "status")) {
		tamt = calculate_owned_coins();
		printf("Unspent coins: %llu.%08llu", tamt / 100000000, tamt % 100000000);
		if (!uptodate) printf(" (Warning: not up to date!)");
		printf("\n");

	// Send coins.
	} else if (!strcmp(command, "send")) {
		if ((count - 1) % 2 != 0) {
			printf("Usage: send <amount> <address> ... <amount> <address>\n");
		}

		amts = malloc(sizeof(uint64_t *) * ((count - 1) / 2));
		addrs = malloc(sizeof(char *) * ((count - 1) / 2));
		memset(delim, ".", 1);
		for (i = 0; i < count - 1; i += 2) {
			tempamt = strtok(args[i], delim);
			if ((temp = strtok(NULL, delim))) {
				amts[i / 2] = strtoull(tempamt, NULL, 10) * 100000000;
				amts[i / 2] += strtoull(temp, NULL, 10);
			} else {
				amts[i / 2] = strtoull(tempamt, NULL, 10);
			}
			tamt += amts[i / 2];
			addrs[i / 2] = args[i + 1];
		}

		if (tamt > calculate_owned_coins()) {
			printf("Not enough coins!\n");
		}

		printf("Sending coins:");
		for (i = 0; i < (count - 1) / 2; i++) {
			printf(" %llu.%08llu to %s", tamt / 100000000, tamt % 100000000, addrs[i]);
			if (i < ((count - 1) / 2) - 1) printf(",");
			else printf(".\n");
		}
		send_coins(amts, addrs, (count - 1) / 2);
		free(amts);
		free(addrs);

	} else if (!strcmp(command, "show")) {
		if (count > 1) {
			for (i = 0; i < count - 1; i++) {
				if (!strcmp(args[i], "debug")) {
					printf("Showing debug logging.\n");
					debug = true;
				} else if (!strcmp(args[i], "sizes")) {
					printf("Showing receive size logging.\n");
					show_rcv = true;
				} else if (!strcmp(args[i], "blocks")) {
					printf("Showing block logging.\n");
					show_blocks = true;
				} else if (!strcmp(args[i], "timeouts")) {
					printf("Showing timeout logging.\n");
					show_timeouts = true;
				} else {
					cmdGood = false;
				}
			}
		}

	} else if (!strcmp(command, "hide")) {
		if (count > 1) {
			for (i = 0; i < count - 1; i++) {
				if (!strcmp(args[i], "debug")) {
					printf("Hiding debug logging.\n");
					debug = false;
				} else if (!strcmp(args[i], "sizes")) {
					printf("Hiding receive size logging.\n");
					show_rcv = false;
				} else if (!strcmp(args[i], "blocks")) {
					printf("Hiding block logging.\n");
					show_blocks = false;
				} else if (!strcmp(args[i], "timeouts")) {
					printf("Hiding timeout logging.\n");
					show_timeouts = false;
				} else {
					cmdGood = false;
				}
			}
		}

	} else {
		cmdGood = false;
	}

	free(args);

	if (cmdGood) return;

	printf("Command not recognized!\n");
}

/**
 * Calculates number of owned and unspent coins.
 * returns: Number of owned and unspent coins.
 */
uint64_t calculate_owned_coins() {
	unsigned int i;
	uint64_t total;

	for (i = ownedStart; i < numOwned; i++)
		if (CBBlockChainStorageUnspentOutputExists(fullVal, CBByteArrayGetData(ownedOutputs[i].txHash), ownedOutputs[i].outputIndex))
			total += ownedOutputs[i].amount;
		else
			ownedStart++;

	return total;
}

/**
 * Spend coins at a given bitcoin address.
 * spendAmounts: Amounts to spend.
 * addresses: Bitcoin addresses to spend coins at.
 * numSpends: Number of addresses we're spending at.
 */
void send_coins(uint64_t *spendAmounts, char **addresses, int numSpends) {
	CBTransaction *tx;
	CBTransactionOutput *unspentOut;
	CBTransactionInput **ins = NULL;
	CBScript **outScripts, *changeScript;
	CBByteArray **addressba;
	CBAddress **baseAddresses;
	uint64_t totalInputCoins = 0, totalSpend = 0;
	unsigned int i, numins = 0, sig_len;
	bool coinbase;
	uint32_t outputHeight;
	uint8_t inputHash[32], *sig;
	CBInventoryItem *invitem;

	for (i = 0; i < numSpends; i++) {
		totalSpend += spendAmounts[i];
	}

	// Loop through and grab inputs.
	for (i = ownedStart; i < numOwned; i++) {
		// If we have enough coins now, quit.
		if (totalInputCoins >= totalSpend) break;

		// If the output is unspent...
		if (CBBlockChainStorageUnspentOutputExists(fullVal, CBByteArrayGetData(ownedOutputs[i].txHash), ownedOutputs[i].outputIndex)) {
			// Increase count of inputs.
			numins++;
			// Reallocate memory for inputs.
			ins = realloc(ins, sizeof(CBTransactionInput *) * numins);
			// Create new transaction input.
			ins[numins - 1] = CBNewUnsignedTransactionInput(CB_TRANSACTION_INPUT_FINAL, ownedOutputs[i].txHash, ownedOutputs[i].outputIndex);
			// Update total coins.
			totalInputCoins += ownedOutputs[i].amount;
		} else {
			ownedStart++;
		}
	}

	// If we have enough coins...
	if (totalInputCoins >= totalSpend) {
		// Turn addresses into byte arrays.
		addressba = malloc(sizeof(CBByteArray *) * numSpends);
		baseAddresses = malloc(sizeof(CBAddress *) * numSpends);
		for (i = 0; i < numSpends; i++) {
			if (debug) printf("decode address: %s of length %d\n", addresses[i], strlen(addresses[i]));
			addressba[i] = CBNewByteArrayWithDataCopy((uint8_t *)addresses[i], strlen(addresses[i]));
			baseAddresses[i] = CBNewAddressFromString(addressba[i], false);
			if (debug) { printf("decoded address: "); print_hex(CBGetByteArray(baseAddresses[i])); }
		}

		// Setup scripts and script ops. Copy addresses into outputs.
		changeScript = CBNewScriptOfSize(25);
		CBByteArraySetByte(changeScript, 0, CB_SCRIPT_OP_DUP);
		CBByteArraySetByte(changeScript, 1, CB_SCRIPT_OP_HASH160);
		CBByteArraySetByte(changeScript, 2, 20);
		CBByteArraySetByte(changeScript, 23, CB_SCRIPT_OP_EQUALVERIFY);
		CBByteArraySetByte(changeScript, 24, CB_SCRIPT_OP_CHECKSIG);
		outScripts = malloc(sizeof(CBScript *) * numSpends);
		for (i = 0; i < numSpends; i++) {
			outScripts[i] = CBNewByteArrayWithDataCopy(CBByteArrayGetData(changeScript), 25);
			CBByteArraySetBytes(outScripts[i], 3, CBByteArrayGetData(CBByteArraySubReference(CBGetByteArray(baseAddresses[i]), 1, 20)), 20);
		}
		CBByteArraySetBytes(changeScript, 3, CBByteArrayGetData(publicAddr), 20);

		// Create transaction and add inputs.
		tx = CBNewTransaction(0, VERSION);
		tx->inputs = ins;
		tx->inputNum = numins;

		// Add outputs.
		tx->outputs = malloc(sizeof(CBTransactionOutput *) * numSpends + 1);
		tx->outputNum = 2;

		// Create outputs.
		for (i = 0; i < numSpends; i++) {
			tx->outputs[i] = CBNewTransactionOutput(spendAmounts[i], outScripts[i]);
		}
		tx->outputs[numSpends] = CBNewTransactionOutput(totalInputCoins - totalSpend, changeScript);

		// Loop through inputs and get signatures.
		for (i = 0; i < numins; i++) {
			// Get old transaction output.
			unspentOut = CBBlockChainStorageLoadUnspentOutput(fullVal, CBByteArrayGetData(ins[i]->prevOut.hash), ins[i]->prevOut.index, &coinbase, &outputHeight);
			// Get hash for signature.
			if (CBTransactionGetInputHashForSignature(tx, unspentOut->scriptObject, i, CB_SIGHASH_SINGLE, inputHash)) return;
			// Generate signature using private key.
			CBEcdsaSign(inputHash, privateKey, &sig_len, &sig);
			sig_len++;
			sig[sig_len - 1] = CB_SIGHASH_SINGLE;

			// Create script and set bytes.
			ins[i]->scriptObject = CBNewScriptOfSize(sig_len + PUBLIC_KEY_LEN + 2);
			CBByteArraySetByte(CBGetByteArray(ins[i]->scriptObject), 0, sig_len);
			CBByteArraySetBytes(CBGetByteArray(ins[i]->scriptObject), 1, sig, sig_len);
			CBByteArraySetByte(CBGetByteArray(ins[i]->scriptObject), 1 + sig_len, PUBLIC_KEY_LEN);
			CBByteArraySetBytes(CBGetByteArray(ins[i]->scriptObject), 2 + sig_len, publicKey, PUBLIC_KEY_LEN);
			free(sig);
		}

		// Serialize transaction for hash.
		CBGetMessage(tx)->bytes = CBNewByteArrayOfSize(CBTransactionCalculateLength(tx));
		CBTransactionSerialise(tx, false);

		// CBTransaction *testtx = CBNewTransactionFromData(CBGetMessage(tx)->bytes);
		// CBTransactionDeserialise(testtx);

		// if (verify_tx(testtx)) {
		// 	printf("transaction valid\n");
		// } else {
		// 	printf("transaction not valid\n");
		// }

		// Calculate transaction hash and put the data into an inventory item.
		invitem = CBNewInventoryItem(CB_INVENTORY_ITEM_TRANSACTION, CBNewByteArrayWithDataCopy(CBTransactionGetHash(tx), 32));

		// Create inventory broadcast.
		invbroad = CBNewInventoryBroadcast();
		invbroad->items = malloc(sizeof(CBInventoryItem *));
		invbroad->items[0] = invitem;
		invbroad->itemNum = 1;
		invtype = CB_INVENTORY_ITEM_TRANSACTION;

		// Add transaction to known transactions.
		numKnownTx++;
		txs = realloc(txs, sizeof(CBTransaction *) * numKnownTx);
		txs[numKnownTx - 1] = tx;

		// Unmark the spent outputs.
		ownedStart += numins;

		// Cleanup memory.
		free(addressba);
		free(baseAddresses);
	} else {
		printf("Not enough coins!\n");
	}
}

/**
 * Verify that a transaction is valid.
 * tx: The transaction to validate.
 * returns: True if the transaction is valid, false otherwise.
 */
bool verify_tx(CBTransaction *tx) {
	CBTransactionInput *in;
	CBTransactionOutput *prevOut;
	CBScriptStack stack;
	uint32_t i;
	bool coinbase;
	uint32_t outputHeight;

	// Loop through all inputs of transaction.
	for (i = 0; i < tx->inputNum; i++) {
		in = tx->inputs[i];
		// Check if the unspent previous output exists.
		if (!CBBlockChainStorageUnspentOutputExists(fullVal, CBByteArrayGetData(in->prevOut.hash), in->prevOut.index)) {
			return false;
		}

		if (debug) { printf("verifying output %d of transaction ", in->prevOut.index); print_hex(in->prevOut.hash); }

		// Load the previous output.
		prevOut = CBBlockChainStorageLoadUnspentOutput(fullVal, CBByteArrayGetData(in->prevOut.hash), in->prevOut.index, &coinbase, &outputHeight);
		if (!prevOut) {
			return false;
		}

		// Setup script stack.
		stack = CBNewEmptyScriptStack();
		// Run input script to load signature and public key.
		CBScriptExecute(in->scriptObject, &stack, NULL, NULL, 0, false);
		// Run output script to verify input signature.
		if (CBScriptExecute(prevOut->scriptObject, &stack, CBTransactionGetInputHashForSignature, tx, in->prevOut.index, false) != CB_SCRIPT_TRUE) {
			// Failed. Free and return.
			CBFreeScriptStack(stack);
			CBReleaseObject(prevOut);
			return false;
		}

		// Cleanup memory.
		CBFreeScriptStack(stack);
		CBReleaseObject(prevOut);
	}

	// Verification of all inputs succeeded. Return true.
	return true;
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
		if (debug) perror("Error creating client socket");
		return;
	}

	// Setup address struct.
	memset(&addr, sizeof(addr), 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(netAddr->port);
	addr.sin_addr.s_addr = CBByteArrayReadInt32(netAddr->ip, 12);

	if (debug) printf("Attempting connection...\n");

	// Connect to client.
	if (connect(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
		if (debug) perror("Error connecting to client");
		return;
	}

	if (debug) printf("Successful connection.\n");

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
			strcpy(mtype, "version");
			if (debug) printf("version out\n");
			break;
		case CB_MESSAGE_TYPE_GETADDR:
			strcpy(mtype, "getaddr");
			if (debug) printf("getaddr out\n");
			break;
		case CB_MESSAGE_TYPE_GETBLOCKS:
			strcpy(mtype, "getblocks");
			if (debug) printf("getblocks out\n");
			break;
		case CB_MESSAGE_TYPE_GETDATA:
			strcpy(mtype, "getdata");
			if (debug) printf("getdata out\n");
			break;
		case CB_MESSAGE_TYPE_PING:
			strcpy(mtype, "ping");
			if (debug) printf("ping out\n");
			break;
		case CB_MESSAGE_TYPE_PONG:
			strcpy(mtype, "pong");
			if (debug) printf("pong out\n");
			break;
		case CB_MESSAGE_TYPE_VERACK:
			strcpy(mtype, "verack");
			if (debug) printf("verack out\n");
			break;
		case CB_MESSAGE_TYPE_INV:
			strcpy(mtype, "inv");
			if (debug) printf("inv out\n");
			break;
		case CB_MESSAGE_TYPE_TX:
			strcpy(mtype, "tx");
			if (debug) printf("tx out\n");
			break;
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

	CBReleaseObject(message);

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
	qmessage->type = CB_MESSAGE_TYPE_VERSION;

	// Kick off version exchange by sending our version.
	queue_message(peer, qmessage);
	peer->versionSent = true;

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
	int nonce = rand();

	// Setup message details.
	message->type = CB_MESSAGE_TYPE_PING;
	message->bytes = CBNewByteArrayOfSize(4 + sizeof(nonce));
	message->serialised = true;

	CBByteArraySetBytes(message->bytes, 0, (uint8_t *)"ping", 4);
	CBByteArraySetBytes(message->bytes, 0, (uint8_t *)&nonce, sizeof(nonce));

	queue_message(peer, message);
}

/**
 * Constructs and sends a pong message.
 * peer: Peer to send pong message to.
 */
void send_pong(CBPeer *peer, int nonce) {
	CBMessage *message = CBNewMessageByObject();

	// Setup message details.
	message->type = CB_MESSAGE_TYPE_PONG;
	message->bytes = CBNewByteArrayOfSize(4 + sizeof(nonce));
	message->serialised = true;

	CBByteArraySetBytes(message->bytes, 0, (uint8_t *)"pong", 4);
	CBByteArraySetBytes(message->bytes, 0, (uint8_t *)&nonce, sizeof(nonce));	

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
	peer->getAddresses = true;
}

/**
 * Vonstructs and sends a getblocks message.
 * peer: Peer to send getblocks message to.
 */
void send_getblocks(CBPeer *peer) {
	uint32_t message_len;
	CBGetBlocks *getBlocks;
	CBChainDescriptor *chainDesc;
	CBBlock *block;
	CBByteArray *blockHash, *hashStop;
	CBMessage *message, *qmessage;
	bool building = true;
	int step = 1, index = 0, next = 0, branchNum, branchIndex;

	// Initialize chain descriptor.
	chainDesc = CBNewChainDescriptor();

	// Setup branch vars to point to head of main branch.
	branchNum = fullVal->mainBranch;
	branchIndex = fullVal->branches[branchNum].numBlocks - 1;
	
	// Loop and build chain descriptor.
	while (building) {
		// Load block from storage.
		block = CBBlockChainStorageLoadBlock(fullVal, branchIndex, branchNum);
		if (!block) return;

		// Setup branch index/number for next loop.
		branchIndex--;
		if (branchIndex < 0) {
			// If we are past index 0 of branch, check parent branch.
			// If parent branch matches current branch, we are at the end.
			if (fullVal->branches[branchNum].parentBranch == branchNum)
				building = false;
			branchIndex = fullVal->branches[branchNum].parentBlockIndex;
			branchNum = fullVal->branches[branchNum].parentBranch;
		}

		// If we are at the next hash to add...
		if (index == next) {
			// Increase step if index is above 10.
			if (index >= 10) step *= 2;
			// Set next hash index.
			next += step;
			// Get hash and add.
			blockHash = CBNewByteArrayWithDataCopy(CBBlockGetHash(block), 32);
			CBChainDescriptorAddHash(chainDesc, blockHash);
			CBReleaseObject(blockHash);
			blockHash = NULL;
		}
		index++;

		// Cleanup memory.
		CBReleaseObject(block);
		if (blockHash) CBReleaseObject(blockHash);
	}

	// Setup zero hashstop.
	hashStop = CBNewByteArrayOfSize(32);
	CBByteArraySetInt32(hashStop, 0, 0);

	// Initialize get blocks.
	getBlocks = CBNewGetBlocks(VERSION, chainDesc, hashStop);

	if (debug) printf("hashes sent: %d\n", chainDesc->hashNum);

	// Generate serialized data for message.
	message = CBGetMessage(getBlocks);
	message_len = CBGetBlocksCalculateLength(getBlocks);
	message->bytes = CBNewByteArrayOfSize(message_len);
	message_len = CBGetBlocksSerialise(getBlocks, false);

	// Copy message into a message that won't be freed.
	qmessage = CBNewMessageByObject();
	qmessage->type = CB_MESSAGE_TYPE_GETBLOCKS;
	CBInitMessageByData(qmessage, message->bytes);

	queue_message(peer, qmessage);

	// Cleanup memory
	CBReleaseObject(getBlocks);
	CBReleaseObject(hashStop);
	CBFreeChainDescriptor(chainDesc);
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

	queue_message(peer, qmessage);

	// Cleanup memory.
	CBReleaseObject(invbroad);
	invbroad = NULL;
}

/**
 * Send an inv message to a peer.
 * peer: Peer to send inv to.
 */
void send_inv(CBPeer *peer) {
	uint32_t message_len;
	CBMessage *message, *qmessage;

	// Generate serialized data for message.
	message = CBGetMessage(invbroad);
	message_len = CBInventoryBroadcastCalculateLength(invbroad);
	message->bytes = CBNewByteArrayOfSize(message_len);
	message_len = CBInventoryBroadcastSerialise(invbroad, false);

	// Copy message into a message that won't be freed.
	qmessage = CBNewMessageByObject();
	qmessage->type = CB_MESSAGE_TYPE_INV;
	CBInitMessageByData(qmessage, message->bytes);

	queue_message(peer, qmessage);

	// Cleanup memory.
	CBReleaseObject(invbroad);
	invbroad = NULL;
}

/**
 * Send a tx message to a peer.
 * peer: Peer to send transaction to.
 * hash: Hash of the transaction you want to send.
 */
void send_tx(CBPeer *peer, uint8_t *hash) {
	unsigned int i;
	uint32_t message_len;
	CBMessage *message;

	// Loop through known transactions.
	for (i = 0; i < numKnownTx; i++) {
		if (!memcmp(txs[i]->hash, hash, 32)) {
			// Generate serialized data for message.
			message = CBGetMessage(txs[i]);
			message_len = CBTransactionCalculateLength(txs[i]);
			message->bytes = CBNewByteArrayOfSize(message_len);
			message_len = CBTransactionSerialise(txs[i], false);
			message->type = CB_MESSAGE_TYPE_TX;

			queue_message(peer, message);

			return;
		}
	}
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
		if (debug) printf("Wrong netmagic.\n");
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

	bool is_block = !strncmp(header + CB_MESSAGE_HEADER_TYPE, "block\0\0\0\0\0\0\0", 12);

	if (debug && show_rcv && !is_block) printf("%d byte(s): ", tread);

	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12)) {
		// If we received a version header.
		if (debug) printf("version in\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
		// If we received a verack, update the peer info to say we have finished
		// the version exchange.
		peer->versionAck = true;
		if (debug) printf("verack in\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "addr\0\0\0\0\0\0\0\0", 12)) {
		// We've received a addr. Parse the payload for peers.
		if (debug) printf("addr in\n");
		parse_addr((uint8_t *)payload);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "inv\0\0\0\0\0\0\0\0\0", 12)) {
		// We've received an inv header. Parse the payload for inventory.
		if (debug) printf("inv in\n");
		parse_inv((uint8_t *)payload, tread);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "block\0\0\0\0\0\0\0", 12)) {
		// We've received a block header. Parse it into a block and process.
		if (debug && show_blocks) printf("block in\n");
		parse_block((uint8_t *)payload, tread);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "tx\0\0\0\0\0\0\0\0\0\0", 12)) {
		if (debug) printf("tx in\n");
		parse_tx((uint8_t *)payload, tread);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
		if (debug) printf("ping in\n");
		int nonce = payload[4];
		send_pong(peer, nonce);
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "pong\0\0\0\0\0\0\0\0", 12)) {
		if (debug) printf("pong in\n");
	}
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, "getdata\0\0\0\0\0", 12)) {
		if (debug) printf("getdata in\n");
		parse_getdata((uint8_t *)payload, tread, peer);
	}

	// Free payload.
	free(payload);
}

/**
 * Parse an address list and add the addresses.
 * addrlistdata: Pointer to the memory location of the address list.
 */
void parse_addr(uint8_t *addrlistdata) {
	uint64_t j;
	uint8_t *data;
	CBByteArray *bytes, *addrdata;
	CBVarInt var_len;
	CBNetworkAddress *addr;
	CBPeer *findpeer;

	// Decode the varint and get pointer to data.
	bytes = CBNewByteArrayWithDataCopy(addrlistdata, 8);
	var_len = CBVarIntDecode(bytes, 0);
	data = addrlistdata + var_len.size;

	// Loop through address list elements.
	for (j = 0; j < var_len.val; j++) {
		// Copy raw bytes and deserialize.
		addrdata = CBNewByteArrayWithDataCopy(data + (j * 30), 30);
		addr = CBNewNetworkAddressFromData(addrdata, true);
		CBNetworkAddressDeserialise(addr, true);

		// Create peer and check data structure.
		findpeer = CBNewPeerByTakingNetworkAddress(addr);
		CBFindResult find = CBAssociativeArrayFind(&peerSocks, findpeer);

		// If client is not in data structure, connect to the client.
		if (!find.found) {
			// connect_client(findpeer);
		}

		// Cleanup memory.
		CBReleaseObject(findpeer);
		CBReleaseObject(addrdata);
	}

	CBReleaseObject(bytes);
}

/**
 * Parse an inventory list. For right now, it assumes it's a block list.
 * invdata: The raw bytes of the inventory list.
 * length: Length of the raw bytes.
 */
void parse_inv(uint8_t *invdata, unsigned int length) {
	CBByteArray *invbroadba;

	// Check if there was an invbroad ready to send but was never sent.
	if (invbroad) CBReleaseObject(invbroad);

	// Copy raw bytes and deserialise.
	invbroadba = CBNewByteArrayWithDataCopy(invdata, length);
	invbroad = CBNewInventoryBroadcastFromData(invbroadba);
	CBInventoryBroadcastDeserialise(invbroad);
	invtype = CB_INVENTORY_ITEM_BLOCK;

	// We've received the response to getblocks, set inv count and flag.
	lastGetData = invbroad->itemNum;
	getblockssent = false;

	if (debug) printf("items received: %d\n", invbroad->itemNum);
	CBReleaseObject(invbroadba);
}

/**
 * Parse a get data message. Also an inventory list. Calls appropriate sends.
 * gddata: The raw bytes of the invetory list.
 * length: Length of the raw bytes.
 * peer: Peer to send the data back to.
 */
void parse_getdata(uint8_t *gddata, unsigned int length, CBPeer *peer) {
	CBByteArray *invitemsba;
	CBInventoryBroadcast *invitems;
	CBInventoryItem *invitem;
	uint16_t i;

	// Copy raw bytes and deserialise.
	invitemsba = CBNewByteArrayWithDataCopy(gddata, length);
	invitems = CBNewInventoryBroadcastFromData(invitemsba);
	CBInventoryBroadcastDeserialise(invitems);

	// Loop through inventory items...
	for (i = 0; i < invitems->itemNum; i++) {
		invitem = invitems->items[i];
		if (invitem->type == CB_INVENTORY_ITEM_TRANSACTION) {
			send_tx(peer, CBByteArrayGetData(invitem->hash));
		}
	}
}

/**
 * Parse a block.
 * blockdata: Raw byte data of block.
 * length: Length of the raw bytes.
 */
void parse_block(uint8_t *blockdata, unsigned int length) {
	CBByteArray *blockba, *pubKeyHash;
	CBBlock *block;
	CBBlockStatus status;
	uint32_t i, out;
	CBTransaction *tx;
	CBScript *script;

	// Copy raw bytes and deserialise.
	blockba = CBNewByteArrayWithDataCopy(blockdata, length);
	block = CBNewBlockFromData(blockba);
	CBBlockDeserialise(block, true);

	// Process the block.
	status = CBFullValidatorProcessBlock(fullVal, block, time(NULL));

	// If block is ok, check transactions for bitcoins we can spend.
	if (status == CB_BLOCK_STATUS_MAIN) {
		for (i = 0; i < block->transactionNum; i++) {
			tx = block->transactions[i];
			for (out = 0; out < tx->outputNum; out++) {
				script = tx->outputs[out]->scriptObject;
				if (CBByteArrayGetByte(script, 0) == CB_SCRIPT_OP_DUP &&
					CBByteArrayGetByte(script, 1) == CB_SCRIPT_OP_HASH160 &&
					CBByteArrayGetByte(script, 2) == 20 &&
					CBByteArrayGetByte(script, 23) == CB_SCRIPT_OP_EQUALVERIFY &&
					CBByteArrayGetByte(script, 24) == CB_SCRIPT_OP_CHECKSIG) {
					// Standard bitcoin transaction. Compare against our key.
					pubKeyHash = CBByteArraySubReference(script, 3, script->length - 5);
					if (CBByteArrayCompare(publicAddr, pubKeyHash) == CB_COMPARE_EQUAL) {
						ownedOutputs = realloc(ownedOutputs, sizeof(UnspentOutput));
						ownedOutputs[numOwned].txHash = CBNewByteArrayWithDataCopy(tx->hash, 32);
						if (debug) { printf("storing transaction: "); print_hex(ownedOutputs[numOwned].txHash); }
						ownedOutputs[numOwned].outputIndex = out;
						ownedOutputs[numOwned].amount = tx->outputs[out]->value;
						numOwned++;
					}
					CBReleaseObject(pubKeyHash);
				}
			}
		}
	}

	// Reduce count of get data request.
	lastGetData--;
	if (debug && !lastGetData) printf("processing done\n");

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

	CBReleaseObject(tx);
	CBReleaseObject(txba);
}
