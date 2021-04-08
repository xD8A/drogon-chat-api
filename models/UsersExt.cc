#include "UsersExt.h"
#include <drogon/drogon.h>
#include <bcrypt/bcrypt.h>

using namespace drogon_model::sqlite3;

std::int64_t UsersExt::m_expiresIn = 600;
jwt::algorithm::hs256 *UsersExt::m_secretHash = nullptr;

void UsersExt::updateJWT()
{
    std::string secret = "secret";
    auto config = drogon::app().getCustomConfig();
    if (config.isMember("jwt_secret")) {
        auto value = config["jwt_secret"];
        if (value.isString()) {
            secret = value.asString();
        }
        else {
            LOG_WARN << "JWT secret has invalid type in custom config and will be set to " << secret;
        }
    }
    else {
        LOG_WARN << "JWT secret not found in custom config and will be set to " << secret;
    }
    if (config.isMember("jwt_expires_in")) {
        auto value = config["jwt_expires_in"];
        if (value.isInt64()) {
            m_expiresIn = value.asInt64();
        }
        else {
            LOG_WARN << "JWT duration has invalid type in custom config and will be set to " << m_expiresIn;
        }
    }
    else {
        LOG_WARN << "JWT duration not found in custom config and will be set to " << m_expiresIn;
    }
    static auto secretHash = jwt::algorithm::hs256{secret};
    m_secretHash = &secretHash;
}

bool UsersExt::encryptPassword(const std::string &password, std::string& passwordHash) noexcept
{
    if (!password.empty()) {
        const int workload = 12;
        char salt[BCRYPT_HASHSIZE];
        char hash[BCRYPT_HASHSIZE];
        int ret = bcrypt_gensalt(workload, salt);
        if (ret != 0) return false;
        ret = bcrypt_hashpw(password.c_str(), salt, hash);
        if (ret != 0) return false;
        passwordHash = hash;
        return true;
    }
    return false;
}

bool UsersExt::checkPassword(const std::string &password, const std::string &passwordHash) noexcept
{
    if (!password.empty()) {
        if (passwordHash.empty()) return false;
        return 0 == bcrypt_checkpw(password.c_str(), passwordHash.c_str());
    }
    return false;
}

std::string UsersExt::generateToken(const PrimaryKeyType& userId)
{
    if (!m_secretHash) {
        updateJWT();
    }

    auto expiresAt = std::chrono::system_clock::now() + std::chrono::seconds{m_expiresIn};

    auto builder = jwt::create()
            .set_issuer("auth0")
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(expiresAt)
            .set_payload_claim("user", jwt::claim(std::to_string(userId)));
    auto token = builder.sign(*m_secretHash);
    return token;
}

std::optional<UsersExt::PrimaryKeyType> UsersExt::extractUserId(const std::string& token)
{
    if (!m_secretHash) {
        updateJWT();
    }

    auto verifier =  jwt::verify()
            .with_issuer("auth0")
            .allow_algorithm(*m_secretHash);
    try {
        jwt::decoded_jwt<jwt::picojson_traits> decoded = jwt::decode(token);

        try {
            verifier.verify(decoded);
        } catch (const std::exception &e) {
            LOG_ERROR << "Untrusted token: " << e.what();
            return std::nullopt;
        }

        try {
            return stoi(decoded.get_payload_claim("user").as_string());
        } catch (const std::exception &e) {
            LOG_ERROR << "Invalid token payload: " << e.what();
            return std::nullopt;
        }

    } catch (const std::exception &e) {
        LOG_ERROR << "Invalid token: " << e.what();
        return std::nullopt;
    }
}

Json::Value UsersExt::convertJson(const Json::Value& pJson)
{
    Json::Value result(pJson);
    if (result.isMember("password")) {
        const std::string password = result["password"].asString();
        std::string passwordHash;
        if (UsersExt::encryptPassword(password, passwordHash)) {
            result["password_hash"] = passwordHash;
            result.removeMember("password");
        }
    }
    return result;
}

Json::Value UsersExt::convertMasqueradedJson(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector)
{
    Json::Value result(pJson);
    if(pMasqueradingVector.size() <= 3)
    {
        LOG_ERROR << "Bad masquerading vector";
        return result;
    }
    if (result.isMember("password")) {
        const std::string password = result["password"].asString();
        std::string passwordHash;
        if (UsersExt::encryptPassword(password, passwordHash)) {
            result[pMasqueradingVector[3]] = passwordHash;
            result.removeMember("password");
        }
    }
    return result;
}


bool UsersExt::validateJsonForPassword(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("password"))
    {
        auto passwordJson = pJson["password"];
        if(passwordJson.isNull())
        {
            err="The password column cannot be null";
            return false;
        }
        if(!passwordJson.isString())
        {
            err="Type error in the password field";
            return false;
        }
        return true;
    }
    return false;
}

bool UsersExt::isEnabled() noexcept
{
    return 0 == getValueOfIsBanned() && nullptr == getPasswordHash();
}

bool UsersExt::setPassword(const std::string& pPassword) noexcept
{
    std::string hash;
    if (!encryptPassword(pPassword, hash))
        return false;
    setPasswordHash(hash);
    return true;
}

bool UsersExt::checkPassword(const std::string& pPassword) const noexcept
{
    const std::string& hash = *getPasswordHash();
    return checkPassword(pPassword, hash);
}
