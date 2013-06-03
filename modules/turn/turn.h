/**
 * @file turn.h Internal TURN interface
 *
 * Copyright (C) 2010 Creytiv.com
 */

struct turnd {
	struct sa rel_addr;
	struct sa rel_addr6;
	struct hash *ht_alloc;
	uint64_t bytec_tx;
	uint64_t bytec_rx;
	uint64_t errc_tx;
	uint64_t errc_rx;
	uint64_t allocc_tot;
	uint32_t allocc_cur;
	uint32_t lifetime_max;
	uint32_t udp_sockbuf_size;
};

struct chanlist;

struct allocation {
	struct le he;
	struct tmr tmr;
	uint8_t tid[STUN_TID_SIZE];
	struct sa cli_addr;
	struct sa srv_addr;
	struct sa rel_addr;
	struct sa rsv_addr;
	void *cli_sock;
	struct udp_sock *rel_us;
	struct udp_sock *rsv_us;
	char *username;
	struct hash *perms;
	struct chanlist *chans;
	uint64_t dropc_tx;
	uint64_t dropc_rx;
	int proto;
};

void allocate_request(struct turnd *turnd, struct allocation *alx,
		      struct restund_msgctx *ctx, int proto, void *sock,
		      const struct sa *src, const struct sa *dst,
		      const struct stun_msg *msg);
void refresh_request(struct turnd *turnd, struct allocation *al,
		     struct restund_msgctx *ctx,
		     int proto, void *sock, const struct sa *src,
		     const struct stun_msg *msg);
void createperm_request(struct allocation *al, struct restund_msgctx *ctx,
			int proto, void *sock, const struct sa *src,
			const struct stun_msg *msg);
void chanbind_request(struct allocation *al, struct restund_msgctx *ctx,
		      int proto, void *sock, const struct sa *src,
		      const struct stun_msg *msg);
struct turnd *turndp(void);


struct perm;

struct perm *perm_find(const struct hash *ht, const struct sa *addr);
struct perm *perm_create(struct hash *ht, const struct sa *peer,
			 const struct allocation *al);
void perm_refresh(struct perm *perm);
void perm_tx_stat(struct perm *perm, size_t bytc);
void perm_rx_stat(struct perm *perm, size_t bytc);
int  perm_hash_alloc(struct hash **ht, uint32_t bsize);
void perm_status(struct hash *ht, struct mbuf *mb);


struct chan;

struct chan *chan_numb_find(const struct chanlist *cl, uint16_t numb);
struct chan *chan_peer_find(const struct chanlist *cl, const struct sa *peer);
uint16_t chan_numb(const struct chan *chan);
const struct sa *chan_peer(const struct chan *chan);
int  chanlist_alloc(struct chanlist **clp, uint32_t bsize);
void chan_status(const struct chanlist *cl, struct mbuf *mb);
