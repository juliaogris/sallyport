// S1: a bare Worker. Answers every request so the probe measures only
// what the Cloudflare edge does with the TLS ClientHello's ALPN list.
export default {
  async fetch(request) {
    return new Response("s1 bare worker\n", { status: 200 });
  },
};
