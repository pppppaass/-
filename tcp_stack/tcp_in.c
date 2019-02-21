#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

// handling incoming packet for TCP_LISTEN state
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "in tcp_state_listen function");

	struct tcp_sock* c_tsk;

	c_tsk = alloc_tcp_sock();
	c_tsk->sk_sip = cb->daddr;
	c_tsk->sk_dip = cb->saddr;
	c_tsk->sk_sport = cb->dport;
	c_tsk->sk_dport = cb->sport;

	c_tsk->rcv_nxt = cb->seq_end;

	c_tsk->parent = tsk;

	list_add_tail(&c_tsk->list, &tsk->listen_queue);

	tcp_send_control_packet(c_tsk, TCP_SYN|TCP_ACK);

	tcp_set_state(c_tsk, TCP_SYN_RECV);

	if(tcp_hash(c_tsk)){
		log(ERROR, "insert into established_table failed.");
		return;
	}
}

// handling incoming packet for TCP_CLOSED state, by replying TCP_RST
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	tcp_send_reset(cb);
}

// handling incoming packet for TCP_SYN_SENT state
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	if(cb->flags != (TCP_SYN | TCP_ACK))
	{
		tcp_send_reset(cb);
		return;
	}
	tsk->rcv_nxt = cb->seq_end;
	tcp_send_control_packet(tsk, TCP_ACK);
	tcp_set_state(tsk, TCP_ESTABLISHED);
	wake_up(tsk->wait_connect);
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (tsk->snd_una <= cb->ack && cb->ack <= tsk->snd_nxt)
		tcp_update_window(tsk, cb);
}

// handling incoming ack packet for tcp sock in TCP_SYN_RECV state
//
// 1. remove itself from parent's listen queue;
// 2. add itself to parent's accept queue;
// 3. wake up parent (wait_accept) since there is established connection in the
//    queue.
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	list_delete_entry(&tsk->list);
	tcp_sock_accept_enqueue(tsk);
	tcp_set_state(tsk, TCP_ESTABLISHED);
	wake_up(tsk->parent->wait_accept);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (cb->seq < rcv_end && tsk->rcv_nxt <= cb->seq_end) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// put the payload of the incoming packet into rcv_buf, and notify the
// tcp_sock_read (wait_recv)
int tcp_recv_data(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
	wake_up(tsk->wait_recv);
	return 0;
}

// Process an incoming packet as follows:
// 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
// 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
// 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
// 	 4. check whether the sequence number of the packet is valid, if not, drop
// 	    it;
// 	 5. if the TCP_RST bit of the packet is set, close this connection, and
// 	    release the resources of this tcp sock;
// 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
// 	    as valid TCP_SYN has been processed in step 2 & 3;
// 	 7. check if the TCP_ACK bit is set, since every packet (except the first 
//      SYN) should set this bit;
//   8. process the ack of the packet: if it ACKs the outgoing SYN packet, 
//      establish the connection; if it ACKs new data, update the window;
//      if it ACKs the outgoing FIN packet, switch to corresponding state;
//   9. process the payload of the packet: call tcp_recv_data to receive data;
//  10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
//  11. at last, do not forget to reply with TCP_ACK if the connection is alive.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	char cb_flags[32];
	tcp_copy_flags_to_str(cb->flags, cb_flags);
	log(DEBUG, "recived tcp packet %s", cb_flags);
	switch(tsk->state)
	{
		case TCP_CLOSED:
			tcp_state_closed(tsk, cb, packet);
			return;
			break;
		case TCP_LISTEN:
			tcp_state_listen(tsk, cb, packet);
			return;
			break;
		case TCP_SYN_SENT:
			tcp_state_syn_sent(tsk, cb, packet);
			return;
			break;
		default:
			break;
	}

	if(!is_tcp_seq_valid(tsk, cb))
	{
		// drop
		log(ERROR, "received tcp packet with invalid seq, drop it.");
		return ;
	}
	
	if(cb->flags & TCP_RST)
	{
		//close this connection, and release the resources of this tcp sock
		tcp_sock_close(tsk);
		return;
	}

	if(cb->flags & TCP_SYN)
	{
		//reply with TCP_RST and close this connection
		tcp_sock_close(tsk);
		return;
	}

	if(!(cb->flags & TCP_ACK) && !(cb->flags & TCP_FIN))
	{
		//drop
		log(ERROR, "received tcp packet without ack, drop it.");
		return ;
	}
	//process the ack of the packet
	if(tsk->state == TCP_SYN_RECV)
	{
		tcp_state_syn_recv(tsk, cb, packet);
		return;
	}
	if(tsk->state == TCP_FIN_WAIT_1)
	{
		tcp_set_state(tsk, TCP_FIN_WAIT_2);
		return;
	}
	if(tsk->state == TCP_LAST_ACK)
	{
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return;
	}
	if(tsk->state == TCP_FIN_WAIT_2)
	{
		if(cb->flags != (TCP_FIN | TCP_ACK))
		{
			//drop
			log(ERROR, "received tcp packet without FIN|ACK, drop it.");
			return;
		}
		tsk->rcv_nxt = cb->seq_end;
		tcp_send_control_packet(tsk, TCP_ACK);
		// start a timer
		tcp_set_timewait_timer(tsk);
		return;
	}
	//update rcv_wnd
	tsk->rcv_wnd -= cb->pl_len;
	//update snd_wnd
	tcp_update_window_safe(tsk, cb);
	//recive data
	if(cb->pl_len > 0)
		tcp_recv_data(tsk, cb, packet);

	if(cb->flags & TCP_FIN)
	{
		//update the TCP_STATE accordingly
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
		tsk->rcv_nxt = cb->seq_end;
		tcp_send_control_packet(tsk, TCP_ACK);
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
		tcp_set_state(tsk, TCP_LAST_ACK);
		return ;
	}

	//reply with TCP_ACK if the connection is alive
	if(cb->flags != TCP_ACK)
	{
		tsk->rcv_nxt = cb->seq_end;
		tcp_send_control_packet(tsk, TCP_ACK);
	}
}	
