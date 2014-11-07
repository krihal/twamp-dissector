/*
 * Wireshark dissector for unauthenticated TWAMP
 *
 * Written by Kristofer Hallin, 2014
 * kristofer dot hallin at gmail dot com
 */

#include <config.h>
#include <epan/packet.h>
#include <inttypes.h>

/* This port is static for now, should be configurable */
#define TWAMP_PORT 4000

/* Protocol enabled flags */
static int proto_twamp = -1;
static gint ett_twamp = -1;

/* Packet fields */
static int twamp_seq_number = -1;
static int twamp_t0_integer = -1;
static int twamp_t0_fractional = -1;
static int twamp_error_estimate = -1;
static int twamp_mbz1 = -1;
static int twamp_t1_integer = -1;
static int twamp_t1_fractional = -1;
static int twamp_sender_seq_number = -1;
static int twamp_t2_integer = -1;
static int twamp_t2_fractional = -1;
static int twamp_sender_error_estimate = -1;
static int twamp_mbz2 = -1;
static int twamp_sender_ttl = -1;
static int twamp_padding = -1;

/*
 * Dissect the TWAMP packet, increase the offset with 
 * the byte length for each field
 */
static int dissect_twamp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint8 cmdtype = tvb_get_guint8 (tvb, 0);
	proto_item *ti = NULL;
	proto_item *twamp_tree = NULL;

	/* Not a TWAMP packet? Abort */
	if (FALSE)
		return 0;

	/* Clear the column */
	col_set_str (pinfo-> cinfo, COL_PROTOCOL, "TWAMP packet");
	col_clear (pinfo->cinfo, COL_INFO);

	/* Expanded view in Wireshark? Show each field in the packet */
	if (tree) {
		ti = proto_tree_add_item (tree, proto_twamp, tvb, 0, -1, ENC_NA);
		twamp_tree = proto_item_add_subtree (ti, ett_twamp);

		proto_tree_add_item (twamp_tree, twamp_seq_number, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_t0_integer, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_t0_fractional, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_error_estimate, tvb, offset,
				     2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item (twamp_tree, twamp_mbz1, tvb, offset,
				     2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item (twamp_tree, twamp_t1_integer, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_t1_fractional, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_sender_seq_number, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_t2_integer, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_t2_fractional, tvb, offset,
				     4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item (twamp_tree, twamp_sender_error_estimate, tvb, offset,
				     2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item (twamp_tree, twamp_mbz2, tvb, offset,
				     2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item (twamp_tree, twamp_sender_ttl, tvb, offset,
				     1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item (twamp_tree, twamp_padding, tvb, offset,
				     1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* Return the number of bytes we have dissected */
		return offset;
	}

	/* Return the total length */
	return tvb_length(tvb);
}

/*
 * Register the protocol and prettyprint each field in the packet
 */
void proto_register_twamp(void)
{
	/* Holder for all fields with descriptions */
	static hf_register_info hf_twamp[] = {
		{&twamp_seq_number, {"Sequence number", "twamp.seq_number", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_t0_integer, {"TImestamp 0, integer part", "twamp.t0_integer", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_t0_fractional, {"TImestamp 0, fractional part", "twamp.t0_fractional", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_error_estimate, {"Error estimate", "twamp.error_estimate", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_mbz1, {"Must Be Zero", "twamp.mbz1", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_t1_integer, {"Timestamp 1, integer part", "twamp.t1_integer", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_t1_fractional, {"Timestamp 1, fractional part", "twamp.t1_fractional", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_seq_number, {"Sender sequence number", "twamp.sender_seq_number", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_t2_integer, {"TImestamp 2, integer part", "twamp.t2_integer", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_t2_fractional, {"Timestamp 2, fractional part", "twamp.t2_fractional", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_error_estimate, {"Sender error estimate", "twamp.sender_error_estimate", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_mbz2, {"Must Be Zero", "twamp.mbz2", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_ttl, {"Sender TTL", "twamp.sender_ttl", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_padding, {"Packet padding", "twamp.padding", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
	};

	static gint *ett_twamp_arr[] = {
		&ett_twamp
	};

	/* Register the protocol */
	proto_twamp = proto_register_protocol("TwoWay Active Measurement Protocol", "TWAMP",
					      "TWAMP");

	/* Register the field array */
	proto_register_field_array (proto_twamp, hf_twamp,
				    array_length(hf_twamp));

	/* Register the subtree array */
	proto_register_subtree_array (ett_twamp_arr,
				      array_length(ett_twamp_arr));
}

/*
 * Handoff the dissector to Wireshark
 */
void proto_reg_handoff_twamp(void)
{
	static dissector_handle_t twamp_handle;

	/* Create a handle */
	twamp_handle = new_create_dissector_handle(dissect_twamp, proto_twamp);

	/* Register the packet for the rule udp.port == TWAMP_PORT (4000) */
	dissector_add_uint("udp.port", TWAMP_PORT, twamp_handle);
}

