#pragma once
#include "json.hpp"
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace enauth::detail {
// Reject ambiguous duplicate fields and excessive nesting before interpreting
// either a signed envelope or its authenticated payload.
inline nlohmann::json ParseObject(const std::string& text) {
    std::vector<std::set<std::string>> keys;
    auto result = nlohmann::json::parse(text,
        [&keys](int depth, nlohmann::json::parse_event_t event, nlohmann::json& value) {
            if (depth > 32) throw std::runtime_error("JSON nesting limit exceeded");
            if (event == nlohmann::json::parse_event_t::object_start) keys.emplace_back();
            if (event == nlohmann::json::parse_event_t::key &&
                !keys.back().insert(value.get<std::string>()).second)
                throw std::runtime_error("Duplicate JSON field");
            if (event == nlohmann::json::parse_event_t::object_end) keys.pop_back();
            return true;
        });
    if (!result.is_object()) throw std::runtime_error("Expected JSON object");
    return result;
}
inline std::string StringField(const nlohmann::json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string())
        throw std::runtime_error("Missing or invalid response string");
    return object.at(key).get<std::string>();
}
inline long long TimeField(const nlohmann::json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_number_integer() ||
        object.at(key).is_number_unsigned() && object.at(key).get<uint64_t>() > INT64_MAX)
        throw std::runtime_error("Invalid response timestamp");
    auto value = object.at(key).get<long long>();
    if (value < 0) throw std::runtime_error("Invalid response timestamp");
    return value;
}
}
