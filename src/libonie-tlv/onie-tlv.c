#include "onie-tlv.h"

struct tlvinfo {
    int test;
};

struct tlvinfo_tlv {
    int test;
};

/* Allocates a new tlvinfo_handle.
 *
 * Args:
 * - max_size: indicates the maximum size the TLV info can grow to.
 *
 * Return: tlvinfo handle on success or NULL otherwise.
 *
 * Errno is set to ENOMEM in case of error.
 */
tlvinfo_handle tlvinfo_alloc(size_t max_size)
{
    return NULL;
}

/* Free's memory allocated via tlvinfo_alloc() and any TLVs added to 'handle'
 * via tlvinfo_add_tlv().
 *
 * Args:
 * - handle: The handle returned by tlvinfo_alloc().
 */
void tlvinfo_free(tlvinfo_handle handle)
{
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
 * EINVAL: If either handle or tlv is NULL.
 */
bool tlvinfo_add_tlv(tlvinfo_handle handle, struct tlvinfo_tlv *tlv)
{
    return false;
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
 * EINVAL: If either handle or tlv is NULL or the tlv was not found.
 */
bool tlvinfo_delete_tlv(tlvinfo_handle handle, struct tlvinfo_tlv *tlv)
{
    return false;
}

/* Attempts to find a specific TLV.
 *
 * Args:
 * - handle: The tlvinfo handle returned by tlvinfo_alloc().
 * - tlv_type: The tlv type to find. If 'tlv_type' is TLV_TYPE_ANY, it returns
 *             the first TLV after 'start_tlv'.
 * - start_tlv: The tlv to begin the search from. If 'start_tlv' is NULL, it
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
 * EINVAL: If tlv is NULL.
 */
bool tlvinfo_get_tlv(struct tlvinfo_tlv* tlv,
                     int *type,
                     size_t *length,
                     uint8_t **value)
{
    return false;
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
 */
bool tlvinfo_init_tlv(int type,
                      size_t length,
                      uint8_t *value,
                      struct tlvinfo_tlv **tlv)
{
    return false;
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
    return false;
}

/* Converts tlv type to a user friendly string.
 *
 * Args:
 * - tlv_type: The type for which a string representation is requested.
 *
 * Return: Pointer to a TLV type string.
 */
const char * tlvinfo_tlv_type_to_string(uint8_t tlv_type)
{
    return NULL;
}
