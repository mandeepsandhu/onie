#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "onie-tlv.h"

/*
 * TLV Types
 */
#define TLV_CODE_PRODUCT_NAME   0x21
#define TLV_CODE_PART_NUMBER    0x22
#define TLV_CODE_SERIAL_NUMBER  0x23
#define TLV_CODE_MAC_BASE       0x24
#define TLV_CODE_MANUF_DATE     0x25
#define TLV_CODE_DEVICE_VERSION 0x26
#define TLV_CODE_LABEL_REVISION 0x27
#define TLV_CODE_PLATFORM_NAME  0x28
#define TLV_CODE_ONIE_VERSION   0x29
#define TLV_CODE_MAC_SIZE       0x2A
#define TLV_CODE_MANUF_NAME     0x2B
#define TLV_CODE_MANUF_COUNTRY  0x2C
#define TLV_CODE_VENDOR_NAME    0x2D
#define TLV_CODE_DIAG_VERSION   0x2E
#define TLV_CODE_SERVICE_TAG    0x2F
#define TLV_CODE_VENDOR_EXT     0xFD
#define TLV_CODE_CRC_32         0xFE

static const char TLVINFO_ID_STRING[]   = "TlvInfo";
static const int TLVINFO_VERSION_1      = 0x01;
static const int TLV_OVERHEAD           = 17; // TLV header + CRC TLV
static const int TLV_VALUE_MAX_LEN      = 255;
static const int TLV_MAX_SIZE           = 2048;

struct __attribute__ ((__packed__)) tlvinfo_header {
    char        signature[8];
    uint8_t     version;
    uint16_t    total_length;
};

struct tlvinfo {
    size_t max_size, curr_size; //curr_size excludes TLV_OVERHEAD
    struct tlv_node *head, *tail;
};

struct __attribute__ ((__packed__)) tlvinfo_tlv {
    uint8_t type;
    uint8_t length;
    uint8_t value[0];
};

// Doubly-linked list of struct tlv's
struct tlv_node {
    struct tlvinfo_tlv *tlv;
    struct tlv_node *next, *prev;
};

// Similar to container_of macro used in Linux kernel, except that this
// macro assumes the 'member' is a pointer type
#define container_of_ptr_mbr(ptr, type, member) ({                     \
                const typeof( ((type *)0)->member ) __mptr = (ptr);    \
                (type *)( (char *)__mptr - offsetof(type,member) );})

/*
 *  Struct for displaying the TLV codes and names.
 */
struct tlv_code_desc {
    uint8_t m_code;
    const char* m_name;
};

/*
 *  List of TLV codes and names.
 */
static const struct tlv_code_desc tlv_code_list[] = {
    { TLV_CODE_PRODUCT_NAME,    "Product Name"},
    { TLV_CODE_PART_NUMBER,     "Part Number"},
    { TLV_CODE_SERIAL_NUMBER,   "Serial Number"},
    { TLV_CODE_MAC_BASE,        "Base MAC Address"},
    { TLV_CODE_MANUF_DATE,      "Manufacture Date"},
    { TLV_CODE_DEVICE_VERSION,  "Device Version"},
    { TLV_CODE_LABEL_REVISION,  "Label Revision"},
    { TLV_CODE_PLATFORM_NAME,   "Platform Name"},
    { TLV_CODE_ONIE_VERSION,    "ONIE Version"},
    { TLV_CODE_MAC_SIZE,        "MAC Addresses"},
    { TLV_CODE_MANUF_NAME,      "Manufacturer"},
    { TLV_CODE_MANUF_COUNTRY,   "Country Code"},
    { TLV_CODE_VENDOR_NAME,     "Vendor Name"},
    { TLV_CODE_DIAG_VERSION,    "Diag Version"},
    { TLV_CODE_SERVICE_TAG,     "Service Tag"},
    { TLV_CODE_VENDOR_EXT,      "Vendor Extension"},
    { TLV_CODE_CRC_32,          "CRC-32"},
};

// Helper functions
static inline size_t total_tlv_size(tlvinfo_handle handle)
{
    // Total size = size of all TLVs + TLV Info header + size of CRC TLV
    return handle->curr_size + TLV_OVERHEAD;
}

static inline size_t tlv_size(struct tlvinfo_tlv *tlv)
{
    // 2 bytes for type & length values
    return tlv->length + 2;
}

static inline bool is_valid_tlv_type(uint8_t type)
{
    int i;
    for (i = 0; i < sizeof(tlv_code_list)/sizeof(tlv_code_list[0]); i++) {
        if (tlv_code_list[i].m_code == type) {
            return true;
        }
    }
    return false;
}

/* Allocates a new tlvinfo_handle.
 *
 * Args:
 * - max_size: indicates the maximum size the TLV info can grow to.
 *
 * Return: tlvinfo handle on success or NULL otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * ENOMEM: Not enough memory to allocate for the handle
 *
 * EINVAL: max_size is greater than 2048
 */
tlvinfo_handle tlvinfo_alloc(size_t max_size)
{
    tlvinfo_handle handle;

    if (max_size > TLV_MAX_SIZE) {
        errno = -EINVAL;
        return NULL;
    }

    handle = (tlvinfo_handle) malloc(sizeof(struct tlvinfo));

    if (!handle) {
        errno = -ENOMEM;
        return handle;
    }

    handle->max_size = max_size;
    handle->curr_size = 0;
    handle->head = handle->tail = NULL;

    return handle;
}

/* Free's memory allocated via tlvinfo_alloc() and any TLVs added to 'handle'
 * via tlvinfo_add_tlv().
 *
 * Args:
 * - handle: The handle returned by tlvinfo_alloc().
 */
void tlvinfo_free(tlvinfo_handle handle)
{
    struct tlv_node *node = handle->head;

    while (node) {
        struct tlv_node *next = node->next;
        if (node->tlv)
            free(node->tlv);

        free(node);
        node = next;
    }

    free(handle);
}

/* Reads TLV contents from 'data' and adds them to the tlvinfo handle. Callers
 * can then use this handle for modifying the TLV contents.
 *
 * Args:
 * - handle: The tlvinfo handle returned by tlvinfo_alloc().
 * - data: The raw TLV data to read.
 *
 * Return: true on success, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EOVERFLOW: The TLV length set in the TLV info header is greater than
 * 'max_size' set in tlvinfo_alloc().
 *
 * EBADMSG: TLV header or CRC validation failed.
 *
 * EINVAL: If either handle or data is NULL.
 */
bool tlvinfo_read(tlvinfo_handle handle, uint8_t *data)
{
    return false;
}

/* Writes TLV contents pointed to by tlvinfo handle to 'data'.
 *
 * NOTE: This function assumes that 'data' is at least as big as 'max_size'
 * set in tlvinfo_alloc().
 *
 * Args:
 * - handle: The tlvinfo handle returned by tlvinfo_alloc().
 * - data: The raw TLV data to write to.
 *
 * Return: true on success, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EBADMSG: TLV header or CRC validation failed.
 *
 * EINVAL: If either handle or data is NULL.
 */
bool tlvinfo_write(tlvinfo_handle handle, uint8_t *data)
{
    return false;
}

/* Add a specific TLV to the list of TLVs pointed to by handle.
 *
 * Args:
 * - handle: The tlvinfo handle returned by tlvinfo_alloc().
 * - tlv: The TLV to add.
 *
 * Return: true if the TLV was added, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EOVERFLOW: Adding TLV excceds the 'max_size' set in tlvinfo_alloc().
 *
 * EINVAL: If arguments are invalid.
 */
bool tlvinfo_add_tlv(tlvinfo_handle handle, struct tlvinfo_tlv *tlv)
{
    struct tlv_node *node;
    node = container_of_ptr_mbr(tlv, struct tlv_node, tlv);

    if (!handle || !tlv || !node) {
        errno = -EINVAL;
        return false;
    }

    if ((total_tlv_size(handle) + tlv_size(tlv)) > handle->max_size) {
        errno = -EOVERFLOW;
        return false;
    }

    // we should probably check if this TLV is already in the list, otherwise
    // we'll end up creating a loop (run a find_tlv() maybe?)
    handle->curr_size += tlv_size(tlv);

    if (handle->tail) {
        handle->tail->next = node;
        node->prev = handle->tail;
    }

    if (!handle->head)
        handle->head = node;

    handle->tail = node;
    return true;
}

/* Delete a specific TLV from the list of TLVs pointed to by handle and free
 * the memory used by it.
 *
 * Args:
 * - handle: The tlvinfo handle returned by tlvinfo_alloc().
 * - tlv: The TLV to delete.
 *
 * Return: true if the TLV was deleted, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EINVAL: If arguments are invalid.
 */
bool tlvinfo_delete_tlv(tlvinfo_handle handle, struct tlvinfo_tlv *tlv)
{
    struct tlv_node *node;
    node = container_of_ptr_mbr(tlv, struct tlv_node, tlv);

    if (!handle || !tlv || !node) {
        errno = -EINVAL;
        return false;
    }

    node->prev->next = node->next;
    node->next->prev = node->prev;

    free(tlv);
    free(node);
    return true;
}

/* Attempts to find a specific TLV.
 *
 * Args:
 * - handle: The tlvinfo handle returned by tlvinfo_alloc().
 * - tlv_type: The tlv type to find. If 'tlv_type' is TLV_TYPE_ANY, it returns
 *             the first TLV after 'start_tlv'.
 * - start_tlv: The tlv after which to search from. If 'start_tlv' is NULL, it
 *              searches from the beginnig, i.e after the TLV info header.
 *
 * NOTE: If 'tlv_type' is TLV_TYPE_ANY and 'start_tlv' is NULL, it returns the
 * first valid TLV found after the TLV info header.
 *
 * Return: Pointer to the tlv if found, NULL otherwise.
 */
struct tlvinfo_tlv* tlvinfo_find_tlv(tlvinfo_handle handle,
                                     int tlv_type,
                                     struct tlvinfo_tlv *start_tlv)
{
    struct tlv_node *node, *this_node;

    if (!handle) {
        errno = -EINVAL;
        return NULL;
    }

    if (start_tlv) {
        this_node = container_of_ptr_mbr(start_tlv, struct tlv_node, tlv);
        node = this_node->next;
    } else
        node = handle->head;

    while (node) {
        if (tlv_type == TLV_TYPE_ANY || tlv_type == node->tlv->type)
            return node->tlv;

        node = node->next;
    }

    return NULL;
}

/* Read type/length/value fields from a tlv.
 *
 * Args:
 * - tlv: The tlv to read (returned as a call to tlvinfo_find_tlv()).
 * - type: Out param, TLV type.
 * - length: Out param, TLV length.
 * - value: Out param, pointer to raw TLV value.
 *
 * Return: true on successfully reading the TLV contents, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EINVAL: If tlv is NULL or the type is an invalid value.
 */
bool tlvinfo_get_tlv(struct tlvinfo_tlv* tlv,
                     int *type,
                     size_t *length,
                     uint8_t **value)
{
    if (!tlv) {
        errno = -EINVAL;
        return false;
    }

    if (!is_valid_tlv_type(tlv->type)) {
        errno = -EINVAL;
        return false;
    }

    *type = tlv->type;
    *length = tlv->length;
    *value = tlv->value;

    return true;
}

/* Create and initialize a new tlvinfo_tlv.
 *
 * Args:
 * - type: TLV type.
 * - length: length of 'value'.
 * - value: pointer to data to be stored in the TLV.
 *
 * Return: true on success, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EINVAL: if
 *  - type is an invalid TLV type
 *  - length is greater than 255
 *  - value is NULL
 *
 * ENOMEM: Not enough memory to allocate for the tlv
 */
bool tlvinfo_init_tlv(int type,
                      size_t length,
                      uint8_t *value,
                      struct tlvinfo_tlv **tlv)
{
    struct tlv_node *node;
    struct tlvinfo_tlv *tlv_data;

    if (!is_valid_tlv_type(type) || length > TLV_VALUE_MAX_LEN || !value) {
        errno = -EINVAL;
        return false;
    }

    node = (struct tlv_node *) malloc(sizeof(struct tlv_node));
    tlv_data = (struct tlvinfo_tlv *) malloc(sizeof(struct tlvinfo_tlv) + length);

    if (!node || !tlv_data) {
        errno = -ENOMEM;
        return false;
    }

    node->next = node->prev = NULL;

    tlv_data->type = type;
    tlv_data->length = length;
    memcpy(tlv_data->value, value, length);

    node->tlv = tlv_data;

    *tlv = tlv_data;

    return true;
}

/* Gets the host-endian value for this multi-byte TLV.
 *
 * Args:
 * - tlv: The tlv to read.
 * - value: Out param, stores the multi-byte TLV value.
 *
 * Return: true on successfully reading the TLV contents, false otherwise.
 *
 * This function sets errno in the following error conditions:
 *
 * EINVAL: If tlv is NULL or the value could not be converted to a uint16.
 */
bool tlvinfo_get_uint16(struct tlvinfo_tlv *tlv, int *value)
{
    if (!tlv || !is_valid_tlv_type(tlv->type)) {
        errno = -EINVAL;
        return false;
    }

    // Should we verify if the TLV type is a multi-byte type (eg. NUM Macs) ?
    *value = be16toh(*((uint16_t *)tlv->value));

    return true;
}

/* Converts tlv type to a user friendly string.
 *
 * Args:
 * - tlv_type: The type for which a string representation is requested.
 *
 * Return: Pointer to a TLV type string.
 */
const char * tlvinfo_tlv_type_to_string(uint8_t type)
{
    char* name = "Unknown";
    int   i;

    for (i = 0; i < sizeof(tlv_code_list)/sizeof(tlv_code_list[0]); i++) {
        if (tlv_code_list[i].m_code == type) {
            return tlv_code_list[i].m_name;
        }
    }

    return name;
}