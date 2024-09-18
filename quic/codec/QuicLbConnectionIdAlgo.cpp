#include <algorithm>
#include <openssl/aes.h>
#include <quic/codec/QuicLbConnectionIdAlgo.h>
#include <folly/Expected.h>
#include <folly/Random.h>
#include <quic/QuicException.h>
#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>

namespace quic {
// void fourPassEncryption(std::vector<uint8_t> &connId, std::vector<uint8_t> plaintext) {
//   size_t halfLen = (plaintext.size() + 1) / 2;
//   std::vector<uint8_t> left0;
//   std::vector<uint8_t> right0;
//   
//   std::copy(plaintext.begin(), plaintext.begin() + halflen, left0.begin());
//   if (plaintext.size() % 2 == 0) {
//     std::copy(plaintext.begin() + halfLen, plaintext.end(), right0.begin());
//   } else {
//     left0[halflen - 1] &= 0xf0;
//     std::copy(plaintext.begin() + halflen - 1, plaintext.end(), right0.begin());
//     right0[0] &= 0x0f;
//   }
// }

bool QuicLbConnectionIdAlgo::canParse(const ConnectionId& id) const noexcept {
  if (id.size() != config_.connectionIdLength()) {
    return false;
  }
  // TODO: implement
  return true;
}

folly::Expected<ServerConnectionIdParams, QuicInternalException>
QuicLbConnectionIdAlgo::parseConnectionId(const ConnectionId& id) noexcept {
  LOG(WARNING) << "parseConnectionId: " << id.hex();
  auto data = id.data();
  auto s = id.size();
  uint32_t hostId = 0;
  hostId |= data[s - 6] << 24;
  hostId |= data[s - 5] << 16;
  hostId |= data[s - 4] << 8;
  hostId |= data[s - 3];
  uint8_t processId = data[s - 2];
  uint8_t workerId = data[s - 1];

  LOG(WARNING) << "hostID: " << std::to_string(hostId);
  LOG(WARNING) << "processID: " << std::to_string(processId);
  LOG(WARNING) << "workerID: " << std::to_string(workerId);

  return ServerConnectionIdParams(hostId, processId, workerId);
}

folly::Expected<ConnectionId, QuicInternalException>
QuicLbConnectionIdAlgo::encodeConnectionId(
    const ServerConnectionIdParams& params) noexcept {
  LOG(WARNING) << "generating";
  std::vector<uint8_t> connIdData(config_.connectionIdLength());

  folly::Random::secureRandom(connIdData.data(), connIdData.size());
  uint8_t firstOctet = folly::Random::secureRand32();
  firstOctet = (firstOctet >> 3) | (config_.cr << 5);
  connIdData[0] = firstOctet;

  std::vector<uint8_t> plaintext(config_.serverIdLen + config_.nonceLen);
  std::copy(serverId_.begin(), serverId_.end(), plaintext.begin());

  std::vector<uint8_t> nonce(config_.nonceLen);
  folly::Random::secureRandom(nonce.data(), nonce.size());
  // TODO: check if the nonce is not reused
  std::copy(nonce.begin(), nonce.end(), plaintext.begin() + serverId_.size());
  std::copy(plaintext.begin(), plaintext.end(), connIdData.begin() + 1);

  auto s = connIdData.size();
  connIdData[s - 6] = params.hostId >> 24;
  connIdData[s - 5] = params.hostId >> 16;
  connIdData[s - 4] = params.hostId >> 8;
  connIdData[s - 3] = params.hostId;
  connIdData[s - 2] = params.processId;
  connIdData[s - 1] = params.workerId;

  ConnectionId connId = ConnectionId(std::move(connIdData));
  LOG(WARNING) << "encodeConnectionId: " << connId.hex();
  LOG(WARNING) << "hostID: " << std::to_string(params.hostId);
  LOG(WARNING) << "processID: " << std::to_string(params.processId);
  LOG(WARNING) << "workerID: " << std::to_string(params.workerId);
  return connId;
}

}
