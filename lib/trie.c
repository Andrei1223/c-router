#include "trie.h"

// function that creates the root for the tree
struct node *init_trie()
{
    struct node *root = malloc(sizeof(struct node));

    int i;
    for (i = 0; i <= 1; i++)
        root->next[i] = NULL;
    root->data = NULL;
    root->value = -1; // unimportant for root
    root->data_size = 0;
    root->data_index = 0;

    return root;
}

// function that creates a node for the trie
struct node *make_node(uint8_t value)
{
    struct node *node = malloc(sizeof(struct node));

    int i;
    for (i = 0; i <= 1; i++)
        node->next[i] = NULL;

    node->data = NULL;
    node->value = value;
    node->data_size = 0;
    node->data_index = 0;

    return node;
}

// function that frees a node and all it s children
void free_node(struct node *node)
{
    int i;

    if (node == NULL) {
        printf("Unable to free NULL node\n\n");
        return ;
    }

    if (node->data != NULL)
        free(node->data);

    // traverse all the children
    for (i = 0; i <= 1; i++) {
        if (node->next[i] != NULL)
            free_node(node->next[i]);
    }

    free(node);
}

// function that inserts a node into the tree
struct node *insert_node(struct node *root, struct route_table_entry *entry)
{
    struct node *aux = root;

    // get the prefix ip adderss
    uint32_t ip_value = ntohl(entry->prefix);
    uint32_t entry_mask = ntohl(entry->mask);
    
    uint32_t mask = 1 << 31;
    int i;

    // traverse each bit from the ip prefix
    for (i = 0; i <= 31; i++) {
        uint8_t value = (ip_value & mask) == 0 ? 0 : 1;

        // if all the bits from the mask have been traversed stop
        if ((entry_mask & mask) == 0)
            break;

        // if the child doesn t exist
        if (aux->next[value] == NULL)
            aux->next[value] = make_node(value);

        // go to the next node
        aux = aux->next[value];
        mask = mask >> 1;
    }

    // add the element into the data
    if (aux->data_size == 0) {
        // create an array
        aux->data = malloc(AUX_VALUE * sizeof(struct route_table_entry *));
        aux->data_size = AUX_VALUE;

    } else if (aux->data_size == aux->data_index) {
        // allocate more memory
        aux->data = realloc(aux->data, (aux->data_size + AUX_VALUE) * sizeof(struct route_table_entry *));

        aux->data_size += AUX_VALUE;
    }

    ((struct route_table_entry **) aux->data)[aux->data_index] = entry;
    aux->data_index++;

    return root;
}

// function thah returns the element from the aray with the biggest mask value
struct route_table_entry *search_by_mask_length(struct route_table_entry **array, uint16_t size)
{
    struct route_table_entry *result = array[0];
    int i;

    for (i = 0; i < size; i++)
        if (ntohl(result->mask) < ntohl(array[i]->mask))
            result = array[i];

    return result;
}

struct node *make_trie(struct route_table_entry *rtable, size_t size)
{
    struct node *root = init_trie();

    int i;
    for (i = 0; i < size; i++) {
        root = insert_node(root, &rtable[i]);
    }

    return root;
}

// function that returns the data array from the tree node
struct route_table_entry *search_entry(struct node *root, uint32_t ip_addr)
{
    struct node *aux = root;

    // get the prefix ip adderss
    uint32_t ip_value = ntohl(ip_addr);

    // traverse each byte from the ip perfix
    uint32_t mask = 1 << 31;
    int i;

    for (i = 0; i <= 31; i++) {
        uint8_t value = (ip_value & mask) == 0 ? 0 : 1;

        if (aux->next[value] == NULL) {
            break;
        }
        aux = aux->next[value];
        mask = mask >> 1;
    }

    if (aux->data_size == 0) {
        printf("Invalid node in 'search_entry'\n\n");
        return NULL;
    }

    if (aux->data_size >= 2) {
        printf("multiple possible routes with the same mask and prefix\n\n");
        return ((struct route_table_entry **)aux->data)[0];
    }

    return ((struct route_table_entry **)aux->data)[0];
}
