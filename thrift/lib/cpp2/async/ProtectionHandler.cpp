/*
 * Copyright 2015-present Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <thrift/lib/cpp2/async/ProtectionHandler.h>

#include <folly/GLog.h>
#include <folly/io/Cursor.h>
#include <thrift/lib/cpp/transport/TTransportException.h>

namespace apache {
namespace thrift {

void ProtectionHandler::read(Context* ctx, folly::IOBufQueue& q) {

  DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 1";
  if (&inputQueue_ != &q) {

    DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 2";
    // If not the same queue
    inputQueue_.append(q);
  }

  DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 3";
  auto e = folly::try_and_catch<std::exception>([&]() {

    DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 4";
    while (!closing_) {

      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 5";
      if (protectionState_ == ProtectionState::INVALID) {

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 6";
        throw transport::TTransportException("protection state is invalid");
      }

      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 7";
      if (protectionState_ == ProtectionState::INPROGRESS) {

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 8";
        // security is still doing stuff, let's return blank.
        break;
      }

      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 9";
      if (protectionState_ != ProtectionState::VALID) {
        
        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 10";
        // not an encrypted message, so pass-through
        ctx->fireRead(inputQueue_);
        break;
      }

      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 11";
      assert(saslEndpoint_ != nullptr);
      size_t remaining = 0;

      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 12";
      if (!inputQueue_.front() || inputQueue_.front()->empty()) {

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 13";
        break;
      }

      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 14";
      std::unique_ptr<folly::IOBuf> unwrapped;
      // If this is the first message after protection state was set to valid,
      // allow the ability to fall back to plaintext.
      if (allowFallback_) {

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 15";
        if (inputQueue_.chainLength() < 6) {

          DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 16";
          // 4 for frame length + 2 for header magic 0x0fff
          // If less than that, continue buffering
          break;
        }

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 17";
        folly::io::Cursor c(inputQueue_.front());
        if (c.readBE<uint32_t>() >= 2 && c.readBE<uint16_t>() == 0x0fff) {

          DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 18";
          // Frame length is at least 2 and first 2 bytes are the header
          // magic 0x0fff. This is potentially a plaintext message on an
          // encrypted channel because the client timed out and fallen back.
          // Make a copy of inputQueue_.
          // If decryption fails, we try to read again without decrypting.
          // The copy is necessary since a decryption attempt modifies the
          // queue.
          folly::IOBufQueue inputQueueCopy(
              folly::IOBufQueue::cacheChainLength());
          auto copyBuf = inputQueue_.front()->clone();
          copyBuf->unshare();
          inputQueueCopy.append(std::move(copyBuf));

          // decrypt inputQueue_
          auto decryptEx = folly::try_and_catch<std::exception>([&]() {
            unwrapped = saslEndpoint_->unwrap(&inputQueue_, &remaining);
          });

          DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 19";
          if (remaining == 0) {

            DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 20";
            // If we got an entire frame, make sure we try the fallback
            // only once. If we only got a partial frame, we have to try
            // falling back again until we get the full first frame.
            allowFallback_ = false;
          }

          DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 22";
          if (decryptEx) {

            DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 23";
            // If decrypt fails, try reading again without decrypting. This
            // allows a fallback to happen if the timeout happened in the last
            // leg of the handshake.
            inputQueue_ = std::move(inputQueueCopy);
            ctx->fireRead(inputQueue_);
            break;
          }
        } else {

          DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 24";
          // This is definitely not a plaintext header message. We can try
          // decrypting without a copy. unwrap() will handle buffering if
          // we only received a chunk.
          allowFallback_ = false;
          unwrapped = saslEndpoint_->unwrap(&inputQueue_, &remaining);
        }
      } else {
        
        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 25";
        unwrapped = saslEndpoint_->unwrap(&inputQueue_, &remaining);
      }


      DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 27";
      assert(bool(unwrapped) ^ (remaining > 0)); // 1 and only 1 should be true
      if (unwrapped) {

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 28";
        queue_.append(std::move(unwrapped));
        ctx->fireRead(queue_);
      } else {

        DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 29";
        break;
      }
    }
  });

  DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 30";
  if (e) {

    DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 31";
    FB_LOG_EVERY_MS(ERROR, 1000)
        << "Exception in ProtectionHandler::read(): " << e.what();
    ctx->fireReadException(std::move(e));
  }
  // Give ownership back to the main queue if we're not in the inprogress
  // state
  DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 32";
  if (&inputQueue_ != &q && protectionState_ != ProtectionState::INPROGRESS) {
    
    DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 33";
    q.append(inputQueue_);
  }

  DLOG(INFO) << "apache::thrift::ProtectionHandler::read: 34, end";
}

folly::Future<folly::Unit> ProtectionHandler::write(
    Context* ctx,
    std::unique_ptr<folly::IOBuf> buf) {
  if (protectionState_ == ProtectionState::VALID) {
    assert(saslEndpoint_);
    buf = saslEndpoint_->wrap(std::move(buf));
  }
  return ctx->fireWrite(std::move(buf));
}

void ProtectionHandler::protectionStateChanged() {
  // We only want to do this callback in the case where we're switching
  // to a valid protection state.
  if (getContext() && !inputQueue_.empty() &&
      protectionState_ == ProtectionState::VALID) {
    read(getContext(), inputQueue_);
  }
}

folly::Future<folly::Unit> ProtectionHandler::close(Context* ctx) {
  closing_ = true;
  return ctx->fireClose();
}

} // namespace thrift
} // namespace apache
