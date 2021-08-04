/*
 * Copyright 2004-present Facebook, Inc.
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

#pragma once

#include <folly/ExceptionWrapper.h>
#include <folly/String.h>
#include <folly/futures/Future.h>
#include <folly/io/async/EventBase.h>
#include <thrift/lib/cpp/TApplicationException.h>
#include <thrift/lib/cpp/TProcessor.h>
#include <thrift/lib/cpp/concurrency/Thread.h>
#include <thrift/lib/cpp/concurrency/ThreadManager.h>
#include <thrift/lib/cpp/protocol/TProtocolTypes.h>
#include <thrift/lib/cpp/transport/THeader.h>
#include <thrift/lib/cpp2/SerializationSwitch.h>
#include <thrift/lib/cpp2/Thrift.h>
#include <thrift/lib/cpp2/async/ResponseChannel.h>
#include <thrift/lib/cpp2/protocol/Protocol.h>
#include <thrift/lib/cpp2/server/Cpp2ConnContext.h>
#include <thrift/lib/thrift/gen-cpp2/RpcMetadata_types.h>
#include <wangle/deprecated/rx/Observer.h>

namespace apache {
namespace thrift {

class EventTask : public virtual apache::thrift::concurrency::Runnable {
 public:
  EventTask(
      folly::Function<void()>&& taskFunc,
      apache::thrift::ResponseChannel::Request* req,
      folly::EventBase* base,
      bool oneway)
      : taskFunc_(std::move(taskFunc)),
        req_(req),
        base_(base),
        oneway_(oneway) {}

  void run() override 
  {

    DLOG(INFO) << "apache::thrift::EventTask::run: 1";
    if (!oneway_) {

      DLOG(INFO) << "apache::thrift::EventTask::run: 2";
      if (req_ && !req_->isActive()) {

        DLOG(INFO) << "apache::thrift::EventTask::run: 3";
        auto req = req_;
        base_->runInEventBaseThread([req]() { delete req; });

        DLOG(INFO) << "apache::thrift::EventTask::run: 4";
        return;
      }
    }

    DLOG(INFO) << "apache::thrift::EventTask::run: 5";
    taskFunc_();

    DLOG(INFO) << "apache::thrift::EventTask::run: 6, end";
  }

  void expired() {
    if (!oneway_) {
      auto req = req_;
      if (req) {
        base_->runInEventBaseThread([req]() {
          req->sendErrorWrapped(
              folly::make_exception_wrapper<TApplicationException>(
                  "Failed to add task to queue, too full"),
              kQueueOverloadedErrorCode);
          delete req;
        });
      }
    }
  }

 private:
  folly::Function<void()> taskFunc_;
  apache::thrift::ResponseChannel::Request* req_;
  folly::EventBase* base_;
  bool oneway_;
};

class PriorityEventTask : public apache::thrift::concurrency::PriorityRunnable,
                          public EventTask {
 public:
  PriorityEventTask(
      apache::thrift::concurrency::PriorityThreadManager::PRIORITY priority,
      folly::Function<void()>&& taskFunc,
      apache::thrift::ResponseChannel::Request* req,
      folly::EventBase* base,
      bool oneway)
      : EventTask(std::move(taskFunc), req, base, oneway),
        priority_(priority) {}

  apache::thrift::concurrency::PriorityThreadManager::PRIORITY getPriority()
      const override {
    return priority_;
  }
  using EventTask::run;

 private:
  apache::thrift::concurrency::PriorityThreadManager::PRIORITY priority_;
};

class AsyncProcessor : public TProcessorBase {
 public:
  virtual ~AsyncProcessor() {}

  virtual void process(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<folly::IOBuf> buf,
      apache::thrift::protocol::PROTOCOL_TYPES protType,
      Cpp2RequestContext* context,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm) = 0;

  virtual bool isOnewayMethod(
      const folly::IOBuf* buf,
      const transport::THeader* header) = 0;
};

class GeneratedAsyncProcessor : public AsyncProcessor {
 public:
  ~GeneratedAsyncProcessor() override {}

  virtual const char* getServiceName() = 0;

  template <typename Derived, typename ProtocolReader>
  using ProcessFunc = void (Derived::*)(
      std::unique_ptr<apache::thrift::ResponseChannel::Request>,
      std::unique_ptr<folly::IOBuf>,
      std::unique_ptr<ProtocolReader> iprot,
      apache::thrift::Cpp2RequestContext* context,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm);
  template <typename ProcessFunc>
  using ProcessMap = std::unordered_map<std::string, ProcessFunc>;

 protected:
  virtual folly::Optional<std::string> getCacheKey(
      folly::IOBuf* buf,
      apache::thrift::protocol::PROTOCOL_TYPES protType) = 0;

  template <typename ProtocolIn, typename Args>
  static void deserializeRequest(
      Args& args,
      folly::IOBuf* buf,
      ProtocolIn* iprot,
      apache::thrift::ContextStack* c) {
    c->preRead();
    apache::thrift::SerializedMessage smsg;
    smsg.protocolType = iprot->protocolType();
    smsg.buffer = buf;
    c->onReadData(smsg);
    uint32_t bytes = detail::deserializeRequestBody(iprot, &args);
    iprot->readMessageEnd();
    c->postRead(nullptr, bytes);
  }

  template <typename ProtocolOut, typename Result>
  static folly::IOBufQueue serializeResponse(
      const char* method,
      ProtocolOut* prot,
      int32_t protoSeqId,
      apache::thrift::ContextStack* ctx,
      const Result& result) {
    folly::IOBufQueue queue(folly::IOBufQueue::cacheChainLength());
    size_t bufSize = detail::serializedResponseBodySizeZC(prot, &result);
    bufSize += prot->serializedMessageSize(method);
    prot->setOutput(&queue, bufSize);
    ctx->preWrite();
    prot->writeMessageBegin(method, apache::thrift::T_REPLY, protoSeqId);
    detail::serializeResponseBody(prot, &result);
    prot->writeMessageEnd();
    ::apache::thrift::SerializedMessage smsg;
    smsg.protocolType = prot->protocolType();
    smsg.buffer = queue.front();
    ctx->onWriteData(smsg);
    ctx->postWrite(queue.chainLength());
    return queue;
  }

  template <typename ProtocolOut>
  static folly::IOBufQueue serializeException(
      const char* method,
      ProtocolOut* prot,
      int32_t protoSeqId,
      apache::thrift::ContextStack*,
      const apache::thrift::TApplicationException& x) {
    folly::IOBufQueue queue(folly::IOBufQueue::cacheChainLength());
    size_t bufSize = detail::serializedExceptionBodySizeZC(prot, &x);
    bufSize += prot->serializedMessageSize(method);
    prot->setOutput(&queue, bufSize);
    prot->writeMessageBegin(method, apache::thrift::T_EXCEPTION, protoSeqId);
    detail::serializeExceptionBody(prot, &x);
    prot->writeMessageEnd();
    return queue;
  }

  static void processInThreadHookPoint()
  {
    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThreadHookPoint";

  }

  template <
      typename ProtocolIn_,
      typename ProtocolOut_,
      typename ProcessFunc,
      typename ChildType>
  static void processInThread(
      std::unique_ptr<apache::thrift::ResponseChannel::Request> req,
      std::unique_ptr<folly::IOBuf> buf,
      std::unique_ptr<ProtocolIn_> iprot,
      apache::thrift::Cpp2RequestContext* ctx,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      apache::thrift::concurrency::PRIORITY pri,
      apache::thrift::RpcKind kind,
      ProcessFunc processFunc,
      ChildType* childClass) 
  {

    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 1";
    processInThreadHookPoint();

    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 1.1";
    if (kind == apache::thrift::RpcKind::SINGLE_REQUEST_NO_RESPONSE) {

      DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 2";
      if (!req->isOneway() && !req->isStream()) {

        DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 3";
        req->sendReply(std::unique_ptr<folly::IOBuf>());
      }
    }
    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 4";
    if ((req->isStream() &&
         kind != apache::thrift::RpcKind::SINGLE_REQUEST_STREAMING_RESPONSE) ||
        (!req->isStream() &&
         kind == apache::thrift::RpcKind::SINGLE_REQUEST_STREAMING_RESPONSE)) {

      DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 5";
      if (!req->isOneway()) {

        DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 6";
        req->sendErrorWrapped(
            folly::make_exception_wrapper<TApplicationException>(
                TApplicationException::TApplicationExceptionType::
                    UNKNOWN_METHOD,
                "Function kind mismatch"),
            kRequestTypeDoesntMatchServiceFunctionType);
      }

      DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 7, end";
      return;
    }
    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 8";
    auto preq = req.get();
    try {
      tm->add(
          std::make_shared<apache::thrift::PriorityEventTask>(
              pri,
              [=, iprot = std::move(iprot), buf = std::move(buf)]() mutable {

                DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 9";
                auto rq =
                    std::unique_ptr<apache::thrift::ResponseChannel::Request>(
                        preq);

                DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 10";
                if (rq->getTimestamps().getSamplingStatus().isEnabled()) {

                  DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 11";
                  // Since this request was queued, reset the processBegin
                  // time to the actual start time, and not the queue time.
                  rq->getTimestamps().processBegin =
                      apache::thrift::concurrency::Util::currentTimeUsec();
                }

                DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 12";
                // Oneway request won't be canceled if expired. see
                // D1006482 for furhter details.  TODO: fix this
                if (kind !=
                    apache::thrift::RpcKind::SINGLE_REQUEST_NO_RESPONSE) {

                  DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 13";
                  if (!rq->isActive()) {
                    eb->runInEventBaseThread(
                        [rq = std::move(rq)]() mutable { rq.reset(); });

                    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 14";
                    return;
                  }
                }

                DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 15";
                (childClass->*processFunc)(
                    std::move(rq),
                    std::move(buf),
                    std::move(iprot),
                    ctx,
                    eb,
                    tm);

                DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 16";
              },
              preq,
              eb,
              kind == apache::thrift::RpcKind::SINGLE_REQUEST_NO_RESPONSE),
          0, // timeout
          0, // expiration
          true, // cancellable
          true); // numa
      DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 17";
      req.release();
    } catch (const std::exception&) {

      DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 18";
      if (kind != apache::thrift::RpcKind::SINGLE_REQUEST_NO_RESPONSE) {
        req->sendErrorWrapped(
            folly::make_exception_wrapper<TApplicationException>(
                "Failed to add task to queue, too full"),
            kQueueOverloadedErrorCode);
      }
    }

    DLOG(INFO) << "apache::thrift::GeneratedAsyncProcessor::processInThread: 19, end";
  }
};

/**
 * HandlerCallback class for async callbacks.
 *
 * These are constructed by the generated code, and your handler calls
 * either result(value), done(), or exception(ex) to finish the async
 * call.  Only one of these must be called, otherwise your client
 * will likely get confused with multiple response messages.
 *
 *
 * If you passed the HandlerCallback to another thread, you may call
 * the *InThread() version of these methods.  The callback will be
 * called in the correct thread, then it will *delete* itself (because
 * otherwise you wouldnoy know when to delete it). So make sure to
 * .release() the unique_ptr on the HandlerCallback if you call the
 * *InThread() method.
 */
class HandlerCallbackBase {
 protected:
  typedef void (*exnw_ptr)(
      std::unique_ptr<ResponseChannel::Request>,
      int32_t protoSeqId,
      apache::thrift::ContextStack*,
      folly::exception_wrapper,
      Cpp2RequestContext*);

 public:
  HandlerCallbackBase()
      : eb_(nullptr), tm_(nullptr), reqCtx_(nullptr), protoSeqId_(0) {}

  HandlerCallbackBase(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<apache::thrift::ContextStack> ctx,
      exnw_ptr ewp,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      Cpp2RequestContext* reqCtx)
      : req_(std::move(req)),
        ctx_(std::move(ctx)),
        ewp_(ewp),
        eb_(eb),
        tm_(tm),
        reqCtx_(reqCtx),
        protoSeqId_(0) {}

  virtual ~HandlerCallbackBase() {
    // req must be deleted in the eb
    if (req_) {
      DCHECK(eb_);
      eb_->runInEventBaseThread(
          [req = std::move(req_)]() mutable { req.reset(); });
    }
  }

  void exception(std::exception_ptr ex) {
    doException(ex);
  }

  void exception(folly::exception_wrapper ew) {
    doExceptionWrapped(ew);
  }

  // Warning: just like "throw ex", this captures the STATIC type of ex, not
  // the dynamic type.  If you need the dynamic type, then either you should
  // be using exception_wrapper instead of a reference to a base exception type,
  // or your exception hierarchy should be equipped to throw polymorphically,
  // see // http://www.parashift.com/c++-faq/throwing-polymorphically.html
  template <class Exception>
  void exception(const Exception& ex) {
    exception(folly::make_exception_wrapper<Exception>(ex));
  }

  void deleteInThread() {
    getEventBase()->runInEventBaseThread([=]() { delete this; });
  }

  void exceptionInThread(std::exception_ptr ex) {
    getEventBase()->runInEventBaseThread([=]() {
      this->exception(ex);
      delete this;
    });
  }

  void exceptionInThread(folly::exception_wrapper ew) {
    getEventBase()->runInEventBaseThread([=]() {
      this->exception(ew);
      delete this;
    });
  }

  template <class Exception>
  void exceptionInThread(const Exception& ex) {
    exceptionInThread(folly::make_exception_wrapper<Exception>(ex));
  }

  static void exceptionInThread(
      std::unique_ptr<HandlerCallbackBase> thisPtr,
      std::exception_ptr ex) {
    DCHECK(thisPtr);
    thisPtr.release()->exceptionInThread(std::move(ex));
  }

  static void exceptionInThread(
      std::unique_ptr<HandlerCallbackBase> thisPtr,
      folly::exception_wrapper ew) {
    DCHECK(thisPtr);
    thisPtr.release()->exceptionInThread(std::move(ew));
  }

  template <class Exception>
  static void exceptionInThread(
      std::unique_ptr<HandlerCallbackBase> thisPtr,
      const Exception& ex) {
    DCHECK(thisPtr);
    thisPtr.release()->exceptionInThread(ex);
  }

  folly::EventBase* getEventBase() {
    assert(eb_);
    return eb_;
  }

  apache::thrift::concurrency::ThreadManager* getThreadManager() {
    assert(tm_);
    return tm_;
  }

  Cpp2RequestContext* getConnectionContext() {
    return reqCtx_;
  }

  bool isRequestActive() {
    // If req_ is nullptr probably it is not managed by this HandlerCallback
    // object and we just return true. An example can be found in task 3106731
    return !req_ || req_->isActive();
  }

  ResponseChannel::Request* getRequest() {
    return req_.get();
  }

  template <class F>
  void runFuncInQueue(F&& func, bool oneway = false) {
    assert(tm_);
    assert(getEventBase()->isInEventBaseThread());
    auto task = concurrency::FunctionRunner::create(std::forward<F>(func));
    try {
      tm_->add(
          task,
          0, // timeout
          0, // expiration
          true, // cancellable
          true); // numa
    } catch (...) {
      if (oneway) {
        return;
      }

      apache::thrift::TApplicationException ex(
          "Failed to add task to queue, too full");
      if (req_ && ewp_) {
        req_->sendErrorWrapped(
            folly::make_exception_wrapper<TApplicationException>(std::move(ex)),
            kQueueOverloadedErrorCode);
      } else {
        LOG(ERROR) << folly::exceptionStr(ex);
      }
      // task owns the callback. If exception is thrown, task isn't added to
      // thread manager so when task falls out of scope the callback will be
      // destroyed.
    }
  }

 protected:
  // HACK(tudorb): Call this to set up forwarding to the event base and
  // thread manager of the other callback.  Use when you want to create
  // callback wrappers that forward to another callback (and do some
  // pre- / post-processing).
  void forward(const HandlerCallbackBase& other) {
    eb_ = other.eb_;
    tm_ = other.tm_;
    ewp_ = other.ewp_;
  }

  virtual void transform(folly::IOBufQueue& queue) {
    // Do any compression or other transforms in this thread, the same thread
    // that serialization happens on.
    queue.append(transport::THeader::transform(
        queue.move(),
        reqCtx_->getHeader()->getWriteTransforms(),
        reqCtx_->getHeader()->getMinCompressBytes()));
  }

  // Can be called from IO or TM thread
  virtual void doException(std::exception_ptr ex) {
    doExceptionWrapped(folly::exception_wrapper::from_exception_ptr(ex));
  }

  virtual void doExceptionWrapped(folly::exception_wrapper ew) {
    if (req_ == nullptr) {
      LOG(ERROR) << ew.what();
    } else {
      callExceptionInEventBaseThread(ewp_, ew);
    }
  }

  template <typename F, typename T>
  void callExceptionInEventBaseThread(F&& f, T&& ex) {
    if (!f) {
      return;
    }
    if (getEventBase()->isInEventBaseThread()) {
      f(std::move(req_), protoSeqId_, ctx_.get(), ex, reqCtx_);
      ctx_.reset();
    } else {
      getEventBase()->runInEventBaseThread([f = std::forward<F>(f),
                                            req = std::move(req_),
                                            protoSeqId = protoSeqId_,
                                            ctx = std::move(ctx_),
                                            ex = std::forward<T>(ex),
                                            reqCtx = reqCtx_]() mutable {
        f(std::move(req), protoSeqId, ctx.get(), ex, reqCtx);
      });
    }
  }

  void sendReply(folly::IOBufQueue queue) 
  {
    DLOG(INFO) << "apache::thrift::HandlerCallbackBase::sendReply: 1";
    transform(queue);
    if (getEventBase()->isInEventBaseThread()) {

      DLOG(INFO) << "apache::thrift::HandlerCallbackBase::sendReply: 2";
      req_->sendReply(queue.move());
    } else {

      DLOG(INFO) << "apache::thrift::HandlerCallbackBase::sendReply: 3";
      getEventBase()->runInEventBaseThread(
          [req = std::move(req_), queue = std::move(queue)]() mutable {

            DLOG(INFO) << "apache::thrift::HandlerCallbackBase::sendReply: 4";
            req->sendReply(queue.move());

            DLOG(INFO) << "apache::thrift::HandlerCallbackBase::sendReply: 5";
          });
    }

    DLOG(INFO) << "apache::thrift::HandlerCallbackBase::sendReply: 6, end";
  }

  void sendReply(
      folly::IOBufQueue queue,
      apache::thrift::Stream<folly::IOBufQueue>&& stream) {
    transform(queue);
    auto stream_ = std::move(stream).map(
        [](auto&& value) mutable { return value.move(); });
    if (getEventBase()->isInEventBaseThread()) {
      req_->sendStreamReply({queue.move(), std::move(stream_)});
    } else {
      getEventBase()->runInEventBaseThread(
          [req = std::move(req_),
           queue = std::move(queue),
           stream = std::move(stream_)]() mutable {
            req->sendStreamReply({queue.move(), std::move(stream)});
          });
    }
  }

  // Required for this call
  std::unique_ptr<ResponseChannel::Request> req_;
  std::unique_ptr<apache::thrift::ContextStack> ctx_;

  // May be null in a oneway call
  exnw_ptr ewp_;

  // Useful pointers, so handler doesn't need to have a pointer to the server
  folly::EventBase* eb_;
  apache::thrift::concurrency::ThreadManager* tm_;
  Cpp2RequestContext* reqCtx_;

  int32_t protoSeqId_;
};

namespace detail {

// template that typedefs type to its argument, unless the argument is a
// unique_ptr<S>, in which case it typedefs type to S.
template <class S>
struct inner_type {
  typedef S type;
};
template <class S>
struct inner_type<std::unique_ptr<S>> {
  typedef S type;
};

} // namespace detail

template <typename T>
class HandlerCallback : public HandlerCallbackBase {
 public:
  typedef typename detail::inner_type<T>::type ResultType;

 private:
  typedef folly::IOBufQueue (*cob_ptr)(
      int32_t protoSeqId,
      apache::thrift::ContextStack*,
      const ResultType&);

 public:
  HandlerCallback() : cp_(nullptr) {}

  HandlerCallback(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<apache::thrift::ContextStack> ctx,
      cob_ptr cp,
      exnw_ptr ewp,
      int32_t protoSeqId,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      Cpp2RequestContext* reqCtx)
      : HandlerCallbackBase(
            std::move(req),
            std::move(ctx),
            ewp,
            eb,
            tm,
            reqCtx),
        cp_(cp) {
    this->protoSeqId_ = protoSeqId;
  }

  void result(const ResultType& r) {
    doResult(r);
  }
  void result(std::unique_ptr<ResultType> r) {
    doResult(*r);
  }
  void resultInThread(const ResultType& r) {
    result(r);
    delete this;
  }
  void resultInThread(std::unique_ptr<ResultType> r) {
    result(*r);
    delete this;
  }
  void resultInThread(const std::shared_ptr<ResultType>& r) {
    result(*r);
    delete this;
  }

  static void resultInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      const ResultType& r) {
    DCHECK(thisPtr);
    thisPtr.release()->resultInThread(r);
  }
  static void resultInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      std::unique_ptr<ResultType> r) {
    DCHECK(thisPtr);
    thisPtr.release()->resultInThread(std::move(r));
  }
  static void resultInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      const std::shared_ptr<ResultType>& r) {
    DCHECK(thisPtr);
    thisPtr.release()->resultInThread(r);
  }

  void complete(folly::Try<T>&& r) {
    if (r.hasException()) {
      exception(std::move(r.exception()));
    } else {
      result(std::move(r.value()));
    }
  }
  void completeInThread(folly::Try<T>&& r) {
    if (r.hasException()) {
      exceptionInThread(std::move(r.exception()));
    } else {
      resultInThread(std::move(r.value()));
    }
  }
  static void completeInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      folly::Try<T>&& r) {
    DCHECK(thisPtr);
    thisPtr.release()->completeInThread(std::move(r));
  }

 protected:
  virtual void doResult(const ResultType& r) {
    assert(cp_);
    auto queue = cp_(this->protoSeqId_, this->ctx_.get(), r);
    this->ctx_.reset();
    sendReply(std::move(queue));
  }

  cob_ptr cp_;
};

template <typename Response, typename StreamItem>
class HandlerCallback<ResponseAndStream<Response, StreamItem>>
    : public HandlerCallbackBase {
 protected:
  typedef ResponseAndStream<Response, StreamItem> ResultType;

 private:
  typedef ResponseAndStream<folly::IOBufQueue, folly::IOBufQueue> (
      *cob_ptr)(int32_t protoSeqId, ContextStack*, ResultType);

 public:
  HandlerCallback() : cp_(nullptr) {}

  HandlerCallback(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<ContextStack> ctx,
      cob_ptr cp,
      exnw_ptr ewp,
      int32_t protoSeqId,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      Cpp2RequestContext* reqCtx)
      : HandlerCallbackBase(
            std::move(req),
            std::move(ctx),
            ewp,
            eb,
            tm,
            reqCtx),
        cp_(cp) {
    this->protoSeqId_ = protoSeqId;
  }

  void result(ResultType r) {
    doResult(std::move(r));
  }
  void resultInThread(ResultType r) {
    result(std::move(r));
    delete this;
  }

  void complete(folly::Try<ResultType>&& r) {
    if (r.hasException()) {
      exception(std::move(r.exception()));
    } else {
      result(std::move(r.value()));
    }
  }
  void completeInThread(folly::Try<ResultType>&& r) {
    if (r.hasException()) {
      exceptionInThread(std::move(r.exception()));
    } else {
      resultInThread(std::move(r.value()));
    }
  }
  static void completeInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      folly::Try<ResultType>&& r) {
    DCHECK(thisPtr);
    thisPtr.release()->completeInThread(std::move(r));
  }

 protected:
  void doResult(ResultType r) {
    assert(cp_);
    auto responseAndStream =
        cp_(this->protoSeqId_, this->ctx_.get(), std::move(r));
    this->ctx_.reset();
    this->sendReply(
        std::move(responseAndStream.response),
        std::move(responseAndStream.stream));
  }

  cob_ptr cp_;
};

template <typename StreamItem>
class HandlerCallback<Stream<StreamItem>> : public HandlerCallbackBase {
 public:
  typedef Stream<StreamItem> ResultType;

 private:
  typedef ResponseAndStream<folly::IOBufQueue, folly::IOBufQueue> (
      *cob_ptr)(int32_t protoSeqId, ContextStack*, ResultType);

 public:
  HandlerCallback() : cp_(nullptr) {}

  HandlerCallback(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<ContextStack> ctx,
      cob_ptr cp,
      exnw_ptr ewp,
      int32_t protoSeqId,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      Cpp2RequestContext* reqCtx)
      : HandlerCallbackBase(
            std::move(req),
            std::move(ctx),
            ewp,
            eb,
            tm,
            reqCtx),
        cp_(cp) {
    this->protoSeqId_ = protoSeqId;
  }

  void result(ResultType r) {
    doResult(std::move(r));
  }
  void resultInThread(ResultType r) {
    result(std::move(r));
    delete this;
  }

  void complete(folly::Try<ResultType>&& r) {
    if (r.hasException()) {
      exception(std::move(r.exception()));
    } else {
      result(std::move(r.value()));
    }
  }
  void completeInThread(folly::Try<ResultType>&& r) {
    if (r.hasException()) {
      exceptionInThread(std::move(r.exception()));
    } else {
      resultInThread(std::move(r.value()));
    }
  }
  static void completeInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      folly::Try<ResultType>&& r) {
    DCHECK(thisPtr);
    thisPtr.release()->completeInThread(std::move(r));
  }

 protected:
  void doResult(ResultType r) {
    assert(cp_);
    auto responseAndStream =
        cp_(this->protoSeqId_, this->ctx_.get(), std::move(r));
    this->ctx_.reset();
    this->sendReply(
        std::move(responseAndStream.response),
        std::move(responseAndStream.stream));
  }

  cob_ptr cp_;
};

template <>
class HandlerCallback<void> : public HandlerCallbackBase {
  typedef folly::IOBufQueue (
      *cob_ptr)(int32_t protoSeqId, apache::thrift::ContextStack*);

 public:
  typedef void ResultType;

  HandlerCallback() : cp_(nullptr) {}

  HandlerCallback(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<apache::thrift::ContextStack> ctx,
      cob_ptr cp,
      exnw_ptr ewp,
      int32_t protoSeqId,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      Cpp2RequestContext* reqCtx)
      : HandlerCallbackBase(
            std::move(req),
            std::move(ctx),
            ewp,
            eb,
            tm,
            reqCtx),
        cp_(cp) {
    this->protoSeqId_ = protoSeqId;
  }

  ~HandlerCallback() override {}

  void done() {
    doDone();
  }
  void doneInThread() {
    done();
    delete this;
  }
  static void doneInThread(std::unique_ptr<HandlerCallback> thisPtr) {
    DCHECK(thisPtr);
    thisPtr.release()->doneInThread();
  }

  void complete(folly::Try<folly::Unit>&& r) {
    if (r.hasException()) {
      exception(std::move(r.exception()));
    } else {
      done();
    }
  }
  void completeInThread(folly::Try<folly::Unit>&& r) {
    if (r.hasException()) {
      exceptionInThread(std::move(r.exception()));
    } else {
      doneInThread();
    }
  }
  static void completeInThread(
      std::unique_ptr<HandlerCallback> thisPtr,
      folly::Try<folly::Unit>&& r) {
    DCHECK(thisPtr);
    thisPtr.release()->completeInThread(std::move(r));
  }

 protected:
  virtual void doDone() {
    assert(cp_);
    auto queue = cp_(this->protoSeqId_, this->ctx_.get());
    this->ctx_.reset();
    sendReply(std::move(queue));
  }

  cob_ptr cp_;
};

template <typename T>
class StreamingHandlerCallback
    : public HandlerCallbackBase,
      public wangle::Observer<typename detail::inner_type<T>::type> {
 public:
  typedef typename detail::inner_type<T>::type ResultType;

 private:
  typedef folly::IOBufQueue (*cob_ptr)(
      int32_t protoSeqId,
      apache::thrift::ContextStack*,
      const ResultType&);

 public:
  StreamingHandlerCallback(
      std::unique_ptr<ResponseChannel::Request> req,
      std::unique_ptr<apache::thrift::ContextStack> ctx,
      cob_ptr cp,
      exnw_ptr ewp,
      int32_t protoSeqId,
      folly::EventBase* eb,
      apache::thrift::concurrency::ThreadManager* tm,
      Cpp2RequestContext* reqCtx)
      : HandlerCallbackBase(
            std::move(req),
            std::move(ctx),
            ewp,
            eb,
            tm,
            reqCtx),
        cp_(cp) {
    this->protoSeqId_ = protoSeqId;
  }

  void write(const ResultType& r) {
    assert(cp_);
    auto queue = cp_(this->protoSeqId_, ctx_.get(), r);
    sendReplyNonDestructive(std::move(queue), "thrift_stream", "chunk");
  }

  void done() {
    auto queue = cp_(this->protoSeqId_, ctx_.get(), ResultType());
    ctx_.reset();
    sendReply(std::move(queue));
  }

  void doneAndDelete() {
    done();
    delete this;
  }

  void resultInThread(const ResultType&) {
    LOG(FATAL) << "resultInThread";
  }

  // Observer overrides
  void onNext(const ResultType& r) override {
    write(r);
  }

  void onCompleted() override {
    done();
  }

  void onError(wangle::Error e) override {
    exception(e);
  }

 private:
  void sendReplyNonDestructive(
      folly::IOBufQueue queue,
      const std::string& key,
      const std::string& value) {
    transform(queue);
    if (getEventBase()->isInEventBaseThread()) {
      reqCtx_->setHeader(key, value);
      req_->sendReply(queue.move());
    } else {
      auto req_raw = req_.get();
      getEventBase()->runInEventBaseThread(
          [=, queue = std::move(queue)]() mutable {
            reqCtx_->setHeader(key, value);
            req_raw->sendReply(queue.move());
          });
    }
  }

  cob_ptr cp_;
};

class AsyncProcessorFactory {
 public:
  virtual std::unique_ptr<apache::thrift::AsyncProcessor> getProcessor() = 0;
  virtual ~AsyncProcessorFactory() {}
};

class ServerInterface : public AsyncProcessorFactory {
 public:
  ~ServerInterface() override {}

  Cpp2RequestContext* getConnectionContext() {
    return reqCtx_;
  }

  void setConnectionContext(Cpp2RequestContext* c) {
    reqCtx_ = c;
  }

  void setThreadManager(apache::thrift::concurrency::ThreadManager* tm) {
    tm_ = tm;
  }

  apache::thrift::concurrency::ThreadManager* getThreadManager() {
    return tm_;
  }

  folly::Executor::KeepAlive<> getBlockingThreadManager() {
    return BlockingThreadManager::create(tm_);
  }

  void setEventBase(folly::EventBase* eb) {
    folly::RequestEventBase::set(eb);
    eb_ = eb;
  }

  folly::EventBase* getEventBase() {
    return eb_;
  }

  virtual apache::thrift::concurrency::PRIORITY getRequestPriority(
      apache::thrift::Cpp2RequestContext* ctx,
      apache::thrift::concurrency::PRIORITY prio =
          apache::thrift::concurrency::NORMAL) {
    apache::thrift::concurrency::PRIORITY callPriority = ctx->getCallPriority();
    if (callPriority != apache::thrift::concurrency::N_PRIORITIES) {
      return callPriority;
    }
    return prio;
  }

 private:
  class BlockingThreadManager : public folly::Executor {
   public:
    static folly::Executor::KeepAlive<> create(
        concurrency::ThreadManager* executor) {
      return makeKeepAlive(new BlockingThreadManager(executor));
    }
    void add(folly::Func f) override {
      std::shared_ptr<apache::thrift::concurrency::Runnable> task =
          concurrency::FunctionRunner::create(std::move(f));
      try {
        executor_->add(
            std::move(task),
            std::chrono::milliseconds(kTimeout).count(),
            0,
            false,
            false);
        return;
      } catch (...) {
        LOG(FATAL) << "Failed to schedule a task within timeout: "
                   << folly::exceptionStr(std::current_exception());
      }
    }

   private:
    explicit BlockingThreadManager(concurrency::ThreadManager* executor)
        : executor_(folly::getKeepAliveToken(executor)) {}

    bool keepAliveAcquire() override {
      auto keepAliveCount =
          keepAliveCount_.fetch_add(1, std::memory_order_relaxed);
      // We should never increment from 0
      DCHECK(keepAliveCount > 0);
      return true;
    }

    void keepAliveRelease() override {
      auto keepAliveCount =
          keepAliveCount_.fetch_sub(1, std::memory_order_acq_rel);
      DCHECK(keepAliveCount >= 1);
      if (keepAliveCount == 1) {
        delete this;
      }
    }

    static constexpr std::chrono::seconds kTimeout{30};
    std::atomic<size_t> keepAliveCount_{1};
    folly::Executor::KeepAlive<concurrency::ThreadManager> executor_;
  };

  /**
   * This variable is only used for sync calls when in a threadpool it
   * is threadlocal, because the threadpool will probably be
   * processing multiple requests simultaneously, and we don't want to
   * mix up the connection contexts.
   *
   * This threadlocal trick doesn't work for async requests, because
   * multiple async calls can be running on the same thread.  Instead,
   * use the callback->getConnectionContext() method.  This reqCtx_
   * will be NULL for async calls.
   */
  static thread_local Cpp2RequestContext* reqCtx_;
  static thread_local apache::thrift::concurrency::ThreadManager* tm_;
  static thread_local folly::EventBase* eb_;
};

} // namespace thrift
} // namespace apache
