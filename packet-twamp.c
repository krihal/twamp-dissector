#include <config.h>
#include <epan/packet.h>

#define TWAMP_PORT 1234

static int proto_twamp = -1;
static gint ett_twamp = -1;
static int hf_twamp_field = -1;

static const value_string strings_field[] = {
	{ 0x00, "temp 1" },
	{ 0x01, "temp 2" },
	{ 0x00, NULL }
};


static int
dissect_twamp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint8 cmdtype = tvb_get_guint8 (tvb, 0);

	if (FALSE)
		return 0;

	col_set_str (pinfo-> cinfo, COL_PROTOCOL, "twamp communication packet");
	col_clear (pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item *ti = NULL;
		proto_item *twamp_tree = NULL;

		ti = proto_tree_add_item (tree, proto_twamp, tvb, 0, -1, ENC_NA);
		twamp_tree = proto_item_add_subtree (ti, ett_twamp);
		proto_tree_add_item (twamp_tree, hf_twamp_field, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		return offset;
	}

	return tvb_length(tvb);
}
void
proto_register_twamp(void)
{
	static hf_register_info hf_twamp[] = {
		{
			&hf_twamp_field,
			{
				"First field of the packet", "twamp.field",
				FT_UINT8, BASE_DEC_HEX,
				VALS(strings_field), 0x0,
				NULL, HFILL
			},
		}
	};

	static gint *ett_twamp_arr[] = {
		&ett_twamp
	};

	proto_twamp = proto_register_protocol("TWAMP communication", "twamp",
					      "twamp");
	proto_register_field_array (proto_twamp, hf_twamp,
				    array_length(hf_twamp));
	proto_register_subtree_array (ett_twamp_arr,
				      array_length(ett_twamp_arr));
}

void
proto_reg_handoff_twamp(void)
{
	static dissector_handle_t twamp_handle;
	twamp_handle = new_create_dissector_handle (dissect_twamp, proto_twamp);
	dissector_add_uint ("udp.port", TWAMP_PORT, twamp_handle);
}

