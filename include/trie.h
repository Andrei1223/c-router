


#ifndef _TRIE_H_
#define _TRIE_H_

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "lib.h"
#include "protocols.h"

#define AUX_VALUE 100

struct node {
    uint8_t value; // prefix node value
    struct node *next[2]; // max number of children
    size_t data_size; // size of the data array
    uint16_t data_index; // current index in the data array
    void *data; // only for leaf nodes
};

extern struct node *make_trie(struct route_table_entry *rtable, size_t size);

// function that creates the root for the tree
extern struct node *init_trie();

// function that creates a node for the trie
extern struct node *make_node(uint8_t value);

// function that frees a node
extern void free_node(struct node *node);

// function that traverses the tree and adds the element
extern struct node *insert_node(struct node *root, struct route_table_entry *entry);

extern struct route_table_entry *search_entry(struct node *root, uint32_t ip_addr);

#endif