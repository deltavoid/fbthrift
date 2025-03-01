/**
 * Autogenerated by Thrift for src/module.thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated @nocommit
 */

#include "thrift/compiler/test/fixtures/any/gen-cpp2/module_data.h"

#include <thrift/lib/cpp2/gen/module_data_cpp.h>

namespace apache {
namespace thrift {

const std::array<::cpp2::MyUnion::Type, 1> TEnumDataStorage<::cpp2::MyUnion::Type>::values = {{
  type::myString,
}};
const std::array<folly::StringPiece, 1> TEnumDataStorage<::cpp2::MyUnion::Type>::names = {{
  "myString",
}};

const std::array<folly::StringPiece, 1> TStructDataStorage<::cpp2::MyStruct>::fields_names = {{
  "myString",
}};
const std::array<int16_t, 1> TStructDataStorage<::cpp2::MyStruct>::fields_ids = {{
  1,
}};
const std::array<protocol::TType, 1> TStructDataStorage<::cpp2::MyStruct>::fields_types = {{
  TType::T_STRING,
}};

const std::array<folly::StringPiece, 1> TStructDataStorage<::cpp2::MyUnion>::fields_names = {{
  "myString",
}};
const std::array<int16_t, 1> TStructDataStorage<::cpp2::MyUnion>::fields_ids = {{
  1,
}};
const std::array<protocol::TType, 1> TStructDataStorage<::cpp2::MyUnion>::fields_types = {{
  TType::T_STRING,
}};

const std::array<folly::StringPiece, 1> TStructDataStorage<::cpp2::MyException>::fields_names = {{
  "myString",
}};
const std::array<int16_t, 1> TStructDataStorage<::cpp2::MyException>::fields_ids = {{
  1,
}};
const std::array<protocol::TType, 1> TStructDataStorage<::cpp2::MyException>::fields_types = {{
  TType::T_STRING,
}};

} // namespace thrift
} // namespace apache
