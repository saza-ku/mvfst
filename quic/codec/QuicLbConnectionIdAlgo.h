#pragma once

#include <vector>
#include <folly/Expected.h>
#include <quic/QuicException.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>

namespace quic {
class QuicLbConnectionIdAlgo : public ConnectionIdAlgo {
 public:
  QuicLbConnectionIdAlgo(QuicLbConfig config, std::vector<uint8_t> serverId) : config_(config), serverId_(serverId) {};
  ~QuicLbConnectionIdAlgo() override = default;

  bool canParse(const ConnectionId& id) const noexcept override;

  folly::Expected<ServerConnectionIdParams, QuicInternalException>
  parseConnectionId(const ConnectionId& id) noexcept override;

  folly::Expected<ConnectionId, QuicInternalException>
  encodeConnectionId(const ServerConnectionIdParams& params) noexcept override;

 private:
  QuicLbConfig config_;
  std::vector<uint8_t> serverId_;
};

class QuicLbConnectionIdAlgoFactory : public ConnectionIdAlgoFactory {
 public:
  QuicLbConnectionIdAlgoFactory(QuicLbConfig config, std::vector<uint8_t> serverId) : config_(config), serverId_(serverId) {};
  ~QuicLbConnectionIdAlgoFactory() override = default;

  std::unique_ptr<ConnectionIdAlgo> make() override {
    return std::make_unique<QuicLbConnectionIdAlgo>(config_, serverId_);
  }

 private:
  QuicLbConfig config_;
  std::vector<uint8_t> serverId_;
};
} // namespace quic
