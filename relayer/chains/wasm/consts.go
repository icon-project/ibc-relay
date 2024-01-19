package wasm

const (
	// External methods
	MethodCreateClient          = "create_client"
	MethodUpdateClient          = "update_client"
	MethodConnectionOpenInit    = "connection_open_init"
	MethodConnectionOpenTry     = "connection_open_try"
	MethodConnectionOpenAck     = "connection_open_ack"
	MethodConnectionOpenConfirm = "connection_open_confirm"
	MethodChannelOpenInit       = "channel_open_init"
	MethodChannelOpenTry        = "channel_open_try"
	MethodChannelOpenAck        = "channel_open_ack"
	MethodChannelOpenConfirm    = "channel_open_confirm"
	MethodChannelCloseInit      = "channel_close_init"
	MethodChannelCloseConfirm   = "channel_close_confirm"
	MethodSendPacket            = "send_packet"
	MethodRecvPacket            = "receive_packet"
	MethodWriteAcknowledgement  = "write_acknowledgement"
	MethodAcknowledgePacket     = "acknowledgement_packet"
	MethodTimeoutPacket         = "timeout_packet"

	// queryMethods
	MethodGetNextClientSequence     = "get_next_client_sequence"
	MethodGetNextChannelSequence    = "get_next_channel_sequence"
	MethodGetNextConnectionSequence = "get_next_connection_sequence"

	MethodGetNextSequenceSend            = "get_next_sequence_send"
	MethodGetNextSequenceReceive         = "get_next_sequence_receive"
	MethodGetNextSequenceAcknowledgement = "get_next_sequence_acknowledgement"

	MethodGetClientState            = "get_client_state"
	MethodGetChannel                = "get_channel"
	MethodGetConnection             = "get_connection"
	MethodGetConsensusStateByHeight = "get_consensus_state_by_height"

	MethodGetPacketCommitment                = "get_packet_commitment"
	MethodGetPacketAcknowledgementCommitment = "get_packet_acknowledgement_commitment"
	MethodGetPacketReceipt                   = "get_packet_receipt"

	MethodGetAllPorts         = "get_all_ports"
	MethodGetCommitmentPrefix = "get_commitment_prefix"

	MethodGetMissingPacketReceipts        = "get_missing_packet_receipts"
	MethodGetPacketHeights                = "get_packet_heights"
	MethodGetAckHeights                   = "get_ack_heights"
	MethodGetPreviousConsensusStateHeight = "get_previous_consensus_state_height"
)

const (
	ClientPrefix     = "iconclient"
	ConnectionPrefix = "connection"
	ChannelPrefix    = "channel"
)

const (
	ContractAddressSizeMinusPrefix = 59
)
