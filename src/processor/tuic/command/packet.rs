use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::BytesMut;

use crate::processor::tuic::CommandProcessor;
use crate::processor::tuic::context::RuntimeContext;
use crate::protocol::tuic::command::Command;
use crate::protocol::tuic::command::packet::Packet;
use quinn::Connection;
use tracing::{debug, error};

pub struct PacketProcessor {}

#[async_trait]
impl CommandProcessor for PacketProcessor {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Connection,
        command: Option<Command>,
    ) -> Result<bool> {
        context.wait_for_auth().await;

        let packet = if let Some(Command::Packet(p)) = command {
            p
        } else {
            bail!("This must not happen! command: {:?}", command)
        };

        let context = context.clone();

        match packet.only_one_frag() {
            true => {
                let session = context.get_session(packet.assoc_id);

                //send data to server
                let Some(remote_addr) = packet.address.to_socket_address().await else {
                    bail!("Failed to resolve address");
                };

                let response_buf = session.send_and_recv(remote_addr, &packet.payload).await?;

                debug!(
                    "associate(ID:{}) packet(ID: {}) sent and recv {} bytes",
                    &packet.assoc_id,
                    &packet.pkt_id,
                    response_buf.len()
                );

                let response_packets = Packet::get_packets_from(
                    &response_buf,
                    packet.assoc_id,
                    packet.pkt_id,
                    &packet.address,
                );

                for packet in response_packets {
                    // Pre-calculate packet size to avoid buffer reallocation
                    let packet_size = packet.estimate_size();
                    let mut bytes = BytesMut::with_capacity(packet_size);
                    packet.write_to_buf(&mut bytes);
                    connection.send_datagram(bytes.freeze()).context(format!(
                        "Failed to send data to client: {}",
                        &connection.remote_address()
                    ))?;
                }

                debug!(
                    "✅ Successfully processed UDP packet, dest: {} size: {}",
                    &packet.address,
                    response_buf.len()
                );

                Ok(true)
            }
            false => {
                // Multi-fragment packet — reassemble first
                let session = context.get_session(packet.assoc_id);
                let assoc_id = packet.assoc_id;
                let pkt_id = packet.pkt_id;

                // Store this fragment and check if packet is complete
                if let Some(completed_pkt_id) = session.accept(packet) {
                    // All fragments received, get assembled payload
                    if let Some(assembled_payload) =
                        session.take_fragmented_packet(completed_pkt_id)
                    {
                        // Get address from session (saved when first fragment arrived)
                        let Some(address) = session.get_address() else {
                            error!(
                                "No address stored in session for associate_id: {}",
                                assoc_id
                            );
                            return Ok(true);
                        };

                        let Some(remote_addr) = address.to_socket_address().await else {
                            error!("Failed to resolve address: {:?}", address);
                            bail!("Failed to resolve address");
                        };

                        // Send assembled data to server and recv response
                        match session.send_and_recv(remote_addr, &assembled_payload).await {
                            Ok(response_buf) => {
                                let recv_n = response_buf.len();
                                debug!(
                                    "associate(ID:{}) fragmented packet(ID: {}) sent and recv {} bytes from {}",
                                    assoc_id, completed_pkt_id, recv_n, &address
                                );

                                // Send response back to client
                                let response_packets = Packet::get_packets_from(
                                    &response_buf,
                                    assoc_id,
                                    completed_pkt_id,
                                    &address,
                                );

                                for resp_packet in response_packets {
                                    let packet_size = resp_packet.estimate_size();
                                    let mut bytes = BytesMut::with_capacity(packet_size);
                                    resp_packet.write_to_buf(&mut bytes);
                                    connection.send_datagram(bytes.freeze()).context(format!(
                                        "Failed to send data to client: {}",
                                        &connection.remote_address()
                                    ))?;
                                }

                                debug!(
                                    "✅ Successfully processed fragmented UDP packet, dest: {} size: {}",
                                    &address, recv_n
                                );
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to send/recv fragmented packet for associate(ID:{}): {}",
                                    assoc_id, e
                                );
                                return Ok(true);
                            }
                        }
                    }
                } else {
                    // Still waiting for more fragments
                    debug!(
                        "associate(ID:{}) packet(ID: {}) received fragment, waiting for more",
                        assoc_id, pkt_id
                    );
                }

                Ok(true)
            }
        }
    }
}
