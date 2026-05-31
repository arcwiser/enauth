#pragma once

#include <cmath>
#include <numbers>
#include <windows.h>

inline DWORD WIDTH = GetSystemMetrics(SM_CXSCREEN);
inline DWORD HEIGHT = GetSystemMetrics(SM_CYSCREEN);

struct vec2 {
    float x, y;

    bool operator==(const vec2& src) const { return x == src.x && y == src.y; }
    bool operator!=(const vec2& src) const { return !(*this == src); }
    vec2 operator+(const vec2& v) const { return { x + v.x, y + v.y }; }
    vec2 operator-(const vec2& v) const { return { x - v.x, y - v.y }; }
    vec2 operator*(float f) const { return { x * f, y * f }; }
    vec2 operator/(float f) const { return { x / f, y / f }; }
    vec2& operator+=(const vec2& v) { x += v.x; y += v.y; return *this; }
    vec2& operator-=(const vec2& v) { x -= v.x; y -= v.y; return *this; }


    bool IsNull() const {
        return (x == 0.0f && y == 0.0f);
    }

    float length() const { return std::sqrt(x * x + y * y); }
    float distance(const vec2& v) const { return (*this - v).length(); }
};

struct vec4 {
    float w, x, y, z;

    bool IsNull() const {
        return (w == 0.0f && x == 0.0f && y == 0.0f && z == 0.0f);
    }
};

struct view_matrix_t {
    float matrix[4][4];

    float* operator[](int index) {
        return matrix[index];
    }
};

struct vec3 {
    float x, y, z;
    vec3 operator+(const vec3& other) const { return { x + other.x, y + other.y, z + other.z }; }
    vec3 operator-(const vec3& other) const { return { x - other.x, y - other.y, z - other.z }; }
    vec3 operator*(float scalar) const { return { x * scalar, y * scalar, z * scalar }; }
    vec3 operator/(float scalar) const { return { x / scalar, y / scalar, z / scalar }; }
    vec3& operator+=(const vec3& other) { x += other.x; y += other.y; z += other.z; return *this; }
    vec3& operator-=(const vec3& other) { x -= other.x; y -= other.y; z -= other.z; return *this; }
    bool IsNull() const { return (x == 0.0f && y == 0.0f && z == 0.0f); }
    float Length() const { return std::sqrt(x * x + y * y + z * z); }
    float Dot(const vec3& other) const {
        return x * other.x + y * other.y + z * other.z;
    }
    vec3 Cross(const vec3& other) const {
        return {
            y * other.z - z * other.y,
            z * other.x - x * other.z,
            x * other.y - y * other.x
        };
    }

    float distance(const vec3& v) const { return (*this - v).Length(); }

    vec3 Normalize() const {
        float length = std::sqrt(x * x + y * y + z * z);
        if (length == 0.0f) return vec3(0, 0, 0);
        return vec3(x / length, y / length, z / length);
    }
    vec3 Normalized() const { return Normalize(); }
    vec3 RelativeAngle() const {
        return {
            std::atan2(-z, std::hypot(x, y)) * (180.0f / std::numbers::pi_v<float>),
            std::atan2(y, x) * (180.0f / std::numbers::pi_v<float>),
            0.0f
        };
    }
    vec2 W2S(const vec3& pos, const view_matrix_t& matrix, int width, int height) const {
        vec2 out;
        float clipX = matrix.matrix[0][0] * pos.x + matrix.matrix[0][1] * pos.y + matrix.matrix[0][2] * pos.z + matrix.matrix[0][3];
        float clipY = matrix.matrix[1][0] * pos.x + matrix.matrix[1][1] * pos.y + matrix.matrix[1][2] * pos.z + matrix.matrix[1][3];
        float clipW = matrix.matrix[3][0] * pos.x + matrix.matrix[3][1] * pos.y + matrix.matrix[3][2] * pos.z + matrix.matrix[3][3];
        if (clipW < 0.01f)
            return { 0.f, 0.f };
        float invW = 1.0f / clipW;
        clipX *= invW;
        clipY *= invW;
        out.x = (width * 0.5f) + (0.5f * clipX * width);
        out.y = (height * 0.5f) - (0.5f * clipY * height);
        return out;
    }
};

inline bool IsOnScreen2(const vec2& p) {
    return (p.x >= 0 && p.x <= WIDTH && p.y >= 0 && p.y <= HEIGHT);
}

struct rgba {
    float r, g, b, a;

    bool IsNull() const {
        return (r == 0.0f && g == 0.0f && b == 0.0f && a == 0.0f);
    }
};