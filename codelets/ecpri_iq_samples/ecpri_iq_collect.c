/*
 * ecpri_iq_collect.c
 *
 * This codelet extracts I/Q samples from eCPRI user-plane packets.
 * It attaches to the capture_xran_packet hook and processes each
 * eCPRI IQ Data message, extracting:
 *   - Radio application metadata (frame, subframe, slot, symbol, section, PRBs)
 *   - Compression info (method, IQ width)
 *   - Raw compressed I/Q payload bytes
 *
 * A configurable sampling parameter controls output rate:
 *   - sampling_period = 0: output every packet (no sampling)
 *   - sampling_period = N: output every Nth symbol (skip N-1, send 1)
 */

#include "jbpf_defs.h"
#include "jbpf_helper.h"
#include "../utils/misc_utils.h"
#include "../utils/net_utils.h"
#include "../xran_packets/xran_format.h"
#include "jbpf_srsran_contexts.h"
#include "ecpri_iq_data.h"

/* ---- Maps ---- */

/* Ringbuf output map for I/Q sample data */
jbpf_ringbuf_map(output_map, struct iq_sample_data, 64);

/* Temporary storage for building the output struct (verifier requires map-backed memory) */
struct jbpf_load_map_def SEC("maps") output_tmp_map = {
    .type = JBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct iq_sample_data),
    .max_entries = 1,
};

/* Sampling configuration: sampling_period (0 = all packets, N = every Nth symbol) */
struct jbpf_load_map_def SEC("maps") sampling_config = {
    .type = JBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
};

/* Symbol counter for sampling */
struct jbpf_load_map_def SEC("maps") symbol_counter = {
    .type = JBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
};


/* ---- Constants ---- */

#define ECPRI_ETH_TYPE (0xaefe)

/* Maximum number of bytes to copy in the bounded loop.
 * Must match MAX_IQ_PAYLOAD_BYTES from ecpri_iq_data.h.
 * The loop is bounded to this value for the verifier. */
#define COPY_LOOP_MAX MAX_IQ_PAYLOAD_BYTES


/* ---- Main codelet entry ---- */

SEC("jbpf_ran_ofh")
uint64_t jbpf_main(void *state)
{
    struct jbpf_ran_ofh_ctx *ctx;
    ctx = (struct jbpf_ran_ofh_ctx *)state;
    int zero_index = 0;

    void *pkt_start = (void *)ctx->data;
    void *pkt_end = (void *)ctx->data_end;

    /* --- Parse Ethernet header --- */
    struct ethhdr *eh = (struct ethhdr *)pkt_start;
    if ((void *)(eh + 1) >= pkt_end) {
        return JBPF_CODELET_FAILURE;
    }

    void *next_hdr = (__u8 *)eh + sizeof(struct ethhdr);
    uint16_t ether_type = jbpf_ntohs(eh->h_proto);

    /* --- Handle optional VLAN tag --- */
    if (ether_type == ETH_P_8021Q) {
        struct vlan_hdr *vl_hdr = (struct vlan_hdr *)next_hdr;
        if ((void *)(vl_hdr + 1) >= pkt_end) {
            return JBPF_CODELET_FAILURE;
        }
        ether_type = jbpf_ntohs(vl_hdr->h_vlan_encapsulated_proto);
        next_hdr = (__u8 *)next_hdr + sizeof(struct vlan_hdr);
    }

    /* Only process eCPRI packets */
    if (ether_type != ECPRI_ETH_TYPE) {
        return JBPF_CODELET_FAILURE;
    }

    /* --- Parse eCPRI header --- */
    struct xran_ecpri_hdr *ecpri_hdr = (struct xran_ecpri_hdr *)next_hdr;
    if ((void *)(ecpri_hdr + 1) >= pkt_end) {
        return JBPF_CODELET_FAILURE;
    }
    next_hdr = (__u8 *)next_hdr + sizeof(struct xran_ecpri_hdr);

    /* Only process IQ Data messages (user plane), skip control plane */
    if (ecpri_hdr->cmnhdr.bits.ecpri_mesg_type != ECPRI_IQ_DATA) {
        return JBPF_CODELET_SUCCESS;
    }

    /* --- Parse Radio Application Common Header --- */
    struct radio_app_common_hdr *app_hdr = (struct radio_app_common_hdr *)next_hdr;
    if ((void *)(app_hdr + 1) >= pkt_end) {
        return JBPF_CODELET_FAILURE;
    }
    next_hdr = (__u8 *)next_hdr + sizeof(struct radio_app_common_hdr);

    /* --- Parse Data Section Header --- */
    struct data_section_hdr *data_hdr = (struct data_section_hdr *)next_hdr;
    if ((void *)(data_hdr + 1) >= pkt_end) {
        return JBPF_CODELET_FAILURE;
    }
    next_hdr = (__u8 *)next_hdr + sizeof(struct data_section_hdr);

    /* --- Parse Compression Header --- */
    struct compression_hdr *comp_hdr = (struct compression_hdr *)next_hdr;
    if ((void *)(comp_hdr + 1) >= pkt_end) {
        return JBPF_CODELET_FAILURE;
    }
    next_hdr = (__u8 *)next_hdr + sizeof(struct compression_hdr);

    /* --- Sampling logic --- */
    uint32_t *period = (uint32_t *)jbpf_map_lookup_elem(&sampling_config, &zero_index);
    if (!period) {
        return JBPF_CODELET_FAILURE;
    }

    uint32_t *counter = (uint32_t *)jbpf_map_lookup_elem(&symbol_counter, &zero_index);
    if (!counter) {
        return JBPF_CODELET_FAILURE;
    }

    uint32_t sampling_period = *period;

    if (sampling_period > 0) {
        uint32_t cnt = *counter;
        cnt++;
        *counter = cnt;

        /* Only output when counter reaches sampling_period, then reset */
        if (cnt < sampling_period) {
            return JBPF_CODELET_SUCCESS;
        }
        /* Reset counter */
        *counter = 0;
    }

    /* --- Get output buffer from temp map --- */
    struct iq_sample_data *out = (struct iq_sample_data *)jbpf_map_lookup_elem(&output_tmp_map, &zero_index);
    if (!out) {
        return JBPF_CODELET_FAILURE;
    }

    /* --- Fill metadata --- */
    out->timestamp = jbpf_time_get_ns();
    out->direction = ctx->direction;
    out->frame_id = app_hdr->frame_id;
    out->subframe_id = (uint16_t)(app_hdr->sf_slot_sym.subframe_id);
    out->slot_id = (uint16_t)(app_hdr->sf_slot_sym.slot_id);
    out->symbol_id = (uint16_t)(app_hdr->sf_slot_sym.symb_id);
    out->section_id = (uint16_t)(data_hdr->fields.sect_id);
    out->start_prbu = (uint16_t)(data_hdr->fields.start_prbu);

    uint16_t num_prbu = (uint16_t)(data_hdr->fields.num_prbu);
    /* num_prbu of 0 means max PRB (273) per O-RAN spec */
    if (num_prbu == 0) {
        num_prbu = 273;
    }
    out->num_prbu = num_prbu;

    out->comp_method = comp_hdr->ud_comp_meth;
    out->iq_width = comp_hdr->ud_iq_width;

    /* --- Copy I/Q payload --- */
    /* next_hdr now points to the start of I/Q data (after compression header).
     * For BFP compression, each PRB starts with a 1-byte compression parameter
     * followed by the compressed I/Q samples. We copy the raw bytes as-is. */
    void *iq_start = next_hdr;
    uint64_t avail = (uint64_t)pkt_end - (uint64_t)iq_start;

    uint16_t copy_size = (uint16_t)avail;
    if (copy_size > MAX_IQ_PAYLOAD_BYTES) {
        copy_size = MAX_IQ_PAYLOAD_BYTES;
    }
    out->payload_size = copy_size;

    /* Bounded copy loop for the verifier */
    __u8 *src = (__u8 *)iq_start;
    for (uint16_t i = 0; i < COPY_LOOP_MAX; i++) {
        if (i >= copy_size) {
            break;
        }
        /* Bounds check each byte against packet end */
        if ((void *)(src + i + 1) > pkt_end) {
            break;
        }
        out->iq_payload[i] = src[i];
    }

    /* --- Output --- */
    int ret = jbpf_ringbuf_output(&output_map, (void *)out, sizeof(struct iq_sample_data));
    jbpf_map_clear(&output_tmp_map);

    if (ret < 0) {
        return JBPF_CODELET_FAILURE;
    }

    return JBPF_CODELET_SUCCESS;
}
