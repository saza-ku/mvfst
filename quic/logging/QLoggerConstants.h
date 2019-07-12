/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/String.h>

namespace quic {
constexpr folly::StringPiece kShortHeaderPacketType = "1RTT";
constexpr folly::StringPiece kVersionNegotiationPacketType =
    "VersionNegotiation";
constexpr folly::StringPiece kHTTP3ProtocolType = "QUIC_HTTP3";
constexpr folly::StringPiece kNoError = "no error";
constexpr folly::StringPiece kGracefulExit = "graceful exit";

} // namespace quic
