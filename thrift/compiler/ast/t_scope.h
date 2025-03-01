/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace apache {
namespace thrift {
namespace compiler {

class t_const;
class t_interaction;
class t_service;
class t_type;

/**
 * This represents a scope used for looking up types, services and other AST
 * constructs. Typically, a scope is associated with a t_program. Scopes are not
 * used to determine code generation, but rather to resolve identifiers at parse
 * time.
 */
class t_scope {
 public:
  void add_type(std::string name, const t_type* type) {
    types_[std::move(name)] = type;
  }

  const t_type* find_type(const std::string& name) const {
    return find_or_null(types_, name);
  }

  void add_service(std::string name, const t_service* service) {
    services_[std::move(name)] = service;
  }

  const t_service* find_service(const std::string& name) const {
    return find_or_null(services_, name);
  }

  void add_interaction(std::string name, const t_interaction* interaction) {
    interactions_[std::move(name)] = interaction;
  }

  const t_interaction* find_interaction(const std::string& name) const {
    return find_or_null(interactions_, name);
  }

  void add_constant(std::string name, const t_const* constant);

  const t_const* find_constant(const std::string& name) const {
    return find_or_null(constants_, name);
  }

  bool is_ambiguous_enum_value(const std::string& enum_value_name) const {
    return redefined_enum_values_.find(enum_value_name) !=
        redefined_enum_values_.end();
  }

  std::string get_fully_qualified_enum_value_names(const std::string& name);

  // Dumps the content of type map to stdout.
  void dump() const;

 private:
  template <typename T>
  static const T* find_or_null(
      const std::unordered_map<std::string, const T*>& map,
      const std::string& name) {
    auto it = map.find(name);
    return it != map.end() ? it->second : nullptr;
  }

  // Map of names to types.
  std::unordered_map<std::string, const t_type*> types_;

  // Map of names to constants.
  std::unordered_map<std::string, const t_const*> constants_;

  // Map of names to services.
  std::unordered_map<std::string, const t_service*> services_;

  // Map of names to interactions.
  std::unordered_map<std::string, const t_interaction*> interactions_;

  // Set of enum value names that are redefined and are ambiguous
  // if referred to without the enum name.
  std::unordered_set<std::string> redefined_enum_values_;

  // Map of enum value names to their definition full names.
  std::unordered_map<std::string, std::unordered_set<std::string>> enum_values_;
};

} // namespace compiler
} // namespace thrift
} // namespace apache
