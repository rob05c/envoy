#pragma once

#include "envoy/stats/stats_macros.h"

#include "source/common/common/fmt.h"
#include "source/common/singleton/const_singleton.h"
#include "source/extensions/filters/common/rbac/engine_impl.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace RBAC {

/**
 * All stats for the enforced rules in RBAC filter. @see stats_macros.h
 */
#define ENFORCE_RBAC_FILTER_STATS(COUNTER)                                                         \
  COUNTER(allowed)                                                                                 \
  COUNTER(denied)

/**
 * All stats for the shadow rules in RBAC filter. @see stats_macros.h
 */
#define SHADOW_RBAC_FILTER_STATS(COUNTER)                                                          \
  COUNTER(shadow_allowed)                                                                          \
  COUNTER(shadow_denied)

/**
 * Wrapper struct for shadow rules in RBAC filter stats. @see stats_macros.h
 */
struct RoleBasedAccessControlFilterStats {
  ENFORCE_RBAC_FILTER_STATS(GENERATE_COUNTER_STRUCT)
  SHADOW_RBAC_FILTER_STATS(GENERATE_COUNTER_STRUCT)

  Stats::Scope& scope_;
  const Stats::StatName stats_prefix_;
  Stats::StatNameSetPtr stat_name_set_;
  const Stats::StatName unknown_policy_allowed_;
  const Stats::StatName unknown_policy_denied_;

  // TODO move to initialisation?
  void add_policy(const std::string& name) {
    stat_name_set_->rememberBuiltin(absl::StrCat(name, ".allowed"));
    stat_name_set_->rememberBuiltin(absl::StrCat(name, ".denied"));
  }

  void inc_policy_allowed(absl::string_view name) {
    incCounter(stat_name_set_->getBuiltin(absl::StrCat(name, ".allowed"), unknown_policy_allowed_));
  }

  void inc_policy_denied(absl::string_view name) {
    incCounter(stat_name_set_->getBuiltin(absl::StrCat(name, ".denied"), unknown_policy_denied_));
  }

  void incCounter(Stats::StatName name) {
    Stats::SymbolTable::StoragePtr storage = scope_.symbolTable().join({stats_prefix_, name});
    scope_.counterFromStatName(Stats::StatName(storage.get())).inc();
  }
};

RoleBasedAccessControlFilterStats
generateStats(const std::string& prefix, const std::string& shadow_prefix, Stats::Scope& scope);

template <class ConfigType>
std::unique_ptr<RoleBasedAccessControlEngine>
createEngine(const ConfigType& config, Server::Configuration::ServerFactoryContext& context,
             ProtobufMessage::ValidationVisitor& validation_visitor,
             ActionValidationVisitor& action_validation_visitor) {
  if (config.has_matcher()) {
    if (config.has_rules()) {
      ENVOY_LOG_MISC(warn, "RBAC rules are ignored when matcher is configured");
    }
    return std::make_unique<RoleBasedAccessControlMatcherEngineImpl>(
        config.matcher(), context, action_validation_visitor, EnforcementMode::Enforced);
  }
  if (config.has_rules()) {
    return std::make_unique<RoleBasedAccessControlEngineImpl>(config.rules(), validation_visitor,
                                                              EnforcementMode::Enforced);
  }

  return nullptr;
}

template <class ConfigType>
std::unique_ptr<RoleBasedAccessControlEngine>
createShadowEngine(const ConfigType& config, Server::Configuration::ServerFactoryContext& context,
                   ProtobufMessage::ValidationVisitor& validation_visitor,
                   ActionValidationVisitor& action_validation_visitor) {
  if (config.has_shadow_matcher()) {
    if (config.has_shadow_rules()) {
      ENVOY_LOG_MISC(warn, "RBAC shadow rules are ignored when shadow matcher is configured");
    }
    return std::make_unique<RoleBasedAccessControlMatcherEngineImpl>(
        config.shadow_matcher(), context, action_validation_visitor, EnforcementMode::Shadow);
  }
  if (config.has_shadow_rules()) {
    return std::make_unique<RoleBasedAccessControlEngineImpl>(
        config.shadow_rules(), validation_visitor, EnforcementMode::Shadow);
  }

  return nullptr;
}

std::string responseDetail(const std::string& policy_id);

} // namespace RBAC
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
