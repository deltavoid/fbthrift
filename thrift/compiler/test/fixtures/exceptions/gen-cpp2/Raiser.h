/**
 * Autogenerated by Thrift for src/module.thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated @nocommit
 */
#pragma once

#include <thrift/lib/cpp2/gen/service_h.h>

#include "thrift/compiler/test/fixtures/exceptions/gen-cpp2/RaiserAsyncClient.h"
#include "thrift/compiler/test/fixtures/exceptions/gen-cpp2/module_types.h"

namespace folly {
  class IOBuf;
  class IOBufQueue;
}
namespace apache { namespace thrift {
  class Cpp2RequestContext;
  class BinaryProtocolReader;
  class CompactProtocolReader;
  namespace transport { class THeader; }
}}

namespace cpp2 {

class RaiserSvAsyncIf {
 public:
  virtual ~RaiserSvAsyncIf() {}
  virtual void async_tm_doBland(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) = 0;
  virtual folly::Future<folly::Unit> future_doBland() = 0;
  virtual folly::SemiFuture<folly::Unit> semifuture_doBland() = 0;
  virtual void async_tm_doRaise(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) = 0;
  virtual folly::Future<folly::Unit> future_doRaise() = 0;
  virtual folly::SemiFuture<folly::Unit> semifuture_doRaise() = 0;
  virtual void async_tm_get200(std::unique_ptr<apache::thrift::HandlerCallback<std::unique_ptr<::std::string>>> callback) = 0;
  virtual folly::Future<std::unique_ptr<::std::string>> future_get200() = 0;
  virtual folly::SemiFuture<std::unique_ptr<::std::string>> semifuture_get200() = 0;
  virtual void async_tm_get500(std::unique_ptr<apache::thrift::HandlerCallback<std::unique_ptr<::std::string>>> callback) = 0;
  virtual folly::Future<std::unique_ptr<::std::string>> future_get500() = 0;
  virtual folly::SemiFuture<std::unique_ptr<::std::string>> semifuture_get500() = 0;
};

class RaiserAsyncProcessor;

class RaiserSvIf : public RaiserSvAsyncIf, public apache::thrift::ServerInterface {
 public:
  typedef RaiserAsyncProcessor ProcessorType;
  std::unique_ptr<apache::thrift::AsyncProcessor> getProcessor() override;
  CreateMethodMetadataResult createMethodMetadata() override;


  virtual void doBland();
  folly::Future<folly::Unit> future_doBland() override;
  folly::SemiFuture<folly::Unit> semifuture_doBland() override;
  void async_tm_doBland(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) override;
  virtual void doRaise();
  folly::Future<folly::Unit> future_doRaise() override;
  folly::SemiFuture<folly::Unit> semifuture_doRaise() override;
  void async_tm_doRaise(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) override;
  virtual void get200(::std::string& /*_return*/);
  folly::Future<std::unique_ptr<::std::string>> future_get200() override;
  folly::SemiFuture<std::unique_ptr<::std::string>> semifuture_get200() override;
  void async_tm_get200(std::unique_ptr<apache::thrift::HandlerCallback<std::unique_ptr<::std::string>>> callback) override;
  virtual void get500(::std::string& /*_return*/);
  folly::Future<std::unique_ptr<::std::string>> future_get500() override;
  folly::SemiFuture<std::unique_ptr<::std::string>> semifuture_get500() override;
  void async_tm_get500(std::unique_ptr<apache::thrift::HandlerCallback<std::unique_ptr<::std::string>>> callback) override;
 private:
  std::atomic<apache::thrift::detail::si::InvocationType> __fbthrift_invocation_doBland{apache::thrift::detail::si::InvocationType::AsyncTm};
  std::atomic<apache::thrift::detail::si::InvocationType> __fbthrift_invocation_doRaise{apache::thrift::detail::si::InvocationType::AsyncTm};
  std::atomic<apache::thrift::detail::si::InvocationType> __fbthrift_invocation_get200{apache::thrift::detail::si::InvocationType::AsyncTm};
  std::atomic<apache::thrift::detail::si::InvocationType> __fbthrift_invocation_get500{apache::thrift::detail::si::InvocationType::AsyncTm};
};

class RaiserSvNull : public RaiserSvIf {
 public:
  void doBland() override;
  void doRaise() override;
  void get200(::std::string& /*_return*/) override;
  void get500(::std::string& /*_return*/) override;
};

class RaiserAsyncProcessor : public ::apache::thrift::GeneratedAsyncProcessor {
 public:
  const char* getServiceName() override;
  void getServiceMetadata(apache::thrift::metadata::ThriftServiceMetadataResponse& response) override;
  using BaseAsyncProcessor = void;
 protected:
  RaiserSvIf* iface_;
 public:
  // This is implemented in case the corresponding AsyncProcessorFactory did not implement createMethodMetadata.
  // This can happen if the service is using a custom AsyncProcessorFactory but re-using the same AsyncProcessor.
  void processSerializedCompressedRequest(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::protocol::PROTOCOL_TYPES protType, apache::thrift::Cpp2RequestContext* context, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm) override;
  // By default, this overload will be called for generated services
  void processSerializedCompressedRequestWithMetadata(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, const apache::thrift::AsyncProcessorFactory::MethodMetadata& methodMetadata, apache::thrift::protocol::PROTOCOL_TYPES protType, apache::thrift::Cpp2RequestContext* context, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm) override;
 public:
  using ProcessFuncs = GeneratedAsyncProcessor::ProcessFuncs<RaiserAsyncProcessor>;
  using ProcessMap = GeneratedAsyncProcessor::ProcessMap<ProcessFuncs>;
  static const RaiserAsyncProcessor::ProcessMap& getOwnProcessMap();
 private:
  static const RaiserAsyncProcessor::ProcessMap kOwnProcessMap_;
 private:
  template <typename ProtocolIn_, typename ProtocolOut_>
  void setUpAndProcess_doBland(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void process_doBland(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx,folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <class ProtocolIn_, class ProtocolOut_>
  static apache::thrift::LegacySerializedResponse return_doBland(int32_t protoSeqId, apache::thrift::ContextStack* ctx);
  template <class ProtocolIn_, class ProtocolOut_>
  static void throw_wrapped_doBland(apache::thrift::ResponseChannelRequest::UniquePtr req,int32_t protoSeqId,apache::thrift::ContextStack* ctx,folly::exception_wrapper ew,apache::thrift::Cpp2RequestContext* reqCtx);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void setUpAndProcess_doRaise(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void process_doRaise(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx,folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <class ProtocolIn_, class ProtocolOut_>
  static apache::thrift::LegacySerializedResponse return_doRaise(int32_t protoSeqId, apache::thrift::ContextStack* ctx);
  template <class ProtocolIn_, class ProtocolOut_>
  static void throw_wrapped_doRaise(apache::thrift::ResponseChannelRequest::UniquePtr req,int32_t protoSeqId,apache::thrift::ContextStack* ctx,folly::exception_wrapper ew,apache::thrift::Cpp2RequestContext* reqCtx);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void setUpAndProcess_get200(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void process_get200(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx,folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <class ProtocolIn_, class ProtocolOut_>
  static apache::thrift::LegacySerializedResponse return_get200(int32_t protoSeqId, apache::thrift::ContextStack* ctx, ::std::string const& _return);
  template <class ProtocolIn_, class ProtocolOut_>
  static void throw_wrapped_get200(apache::thrift::ResponseChannelRequest::UniquePtr req,int32_t protoSeqId,apache::thrift::ContextStack* ctx,folly::exception_wrapper ew,apache::thrift::Cpp2RequestContext* reqCtx);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void setUpAndProcess_get500(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void process_get500(apache::thrift::ResponseChannelRequest::UniquePtr req, apache::thrift::SerializedCompressedRequest&& serializedRequest, apache::thrift::Cpp2RequestContext* ctx,folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <class ProtocolIn_, class ProtocolOut_>
  static apache::thrift::LegacySerializedResponse return_get500(int32_t protoSeqId, apache::thrift::ContextStack* ctx, ::std::string const& _return);
  template <class ProtocolIn_, class ProtocolOut_>
  static void throw_wrapped_get500(apache::thrift::ResponseChannelRequest::UniquePtr req,int32_t protoSeqId,apache::thrift::ContextStack* ctx,folly::exception_wrapper ew,apache::thrift::Cpp2RequestContext* reqCtx);
 public:
  RaiserAsyncProcessor(RaiserSvIf* iface) :
      iface_(iface) {}
  ~RaiserAsyncProcessor() override {}
};

} // cpp2
