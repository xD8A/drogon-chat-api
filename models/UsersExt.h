#pragma once
#include "models/Users.h"
#include <jwt-cpp/jwt.h>


class UsersExt : public drogon_model::sqlite3::Users {
public:

    /**
     * Encrypts password by bcrypt and saves hash (+salt).
     * @param password User password.
     * @param passwordHash Output password hash (+salt)
     * @return True if encryption is successful else false.
     */
    static bool encryptPassword(const std::string &password, std::string& passwordHash) noexcept;

    /**
     * Checks password by bcrypt with password hash (+salt).
     * @param password User password.
     * @param passwordHash Password hash (+salt).
     * @return True if password is valid else false.
     */
    static bool checkPassword(const std::string &password, const std::string& passwordHash) noexcept;

    /**
     * Generates JWT token and save user id in payload ({"user": userId}).
     * @param userId User id.
     * @return Token
     */
    static std::string generateToken(const PrimaryKeyType& userId);

    /**
     * Extracts user id from token's payload.
     * @param token JWT token.
     * @return User id.
     */
    static std::optional<PrimaryKeyType> extractUserId(const std::string& token);

    /**
     * Creates user from row.
     * @param r One row of records in the SQL query result.
     * @param indexOffset Set the offset to -1 to access all columns by column names,
     * otherwise access all columns by offsets.
     * @note If the SQL is not a style of 'select * from table_name ...' (select all
     * columns by an asterisk), please set the offset to -1.
     */
    explicit UsersExt(const Row &r, const ssize_t indexOffset = 0) noexcept : Users(r, indexOffset)
    {}

    /**
     * Prepares JSON (encrypts password to password hash).
     * @param pJson Input json.
     * @return Output json.
     */
    static Json::Value convertJson(const Json::Value &pJson);

    static Json::Value convertMasqueradedJson(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector);

    /**
     * Creates user from json.
     * @param pJson The json object to construct a new instance.
     */
    explicit UsersExt(const Json::Value &pJson) noexcept(false) : drogon_model::sqlite3::Users(convertJson(pJson)) {}

    /**
     * Create user from masqueraded json.
     * @param pJson The json object to construct a new instance.
     * @param pMasqueradingVector The aliases of table columns.
     */
    UsersExt(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false) :
        drogon_model::sqlite3::Users(convertMasqueradedJson(pJson, pMasqueradingVector), pMasqueradingVector)
    {}

    UsersExt() = default;

    void updateByJson(const Json::Value &pJson) noexcept(false)  {
        drogon_model::sqlite3::Users::updateByJson(convertJson(pJson));
    }
    void updateByMasqueradedJson(const Json::Value &pJson,
                                 const std::vector<std::string> &pMasqueradingVector) noexcept(false) {
        drogon_model::sqlite3::Users::updateByMasqueradedJson(convertMasqueradedJson(pJson, pMasqueradingVector),
                                                              pMasqueradingVector);
    }
    static bool validateJsonForPassword(const Json::Value &pJson, std::string &err);

    static bool validateJsonForCreation(const Json::Value &pJson, std::string &err)
    {
        if (!validateJsonForPassword(pJson, err))
            return false;
        return drogon_model::sqlite3::Users::validateJsonForCreation(pJson, err);
    }
    static bool validateMasqueradedJsonForCreation(const Json::Value & pJson,
                                                  const std::vector<std::string> &pMasqueradingVector,
                                                  std::string &err)
    {
        if (!validateJsonForPassword(pJson, err))
            return false;
        return drogon_model::sqlite3::Users::validateMasqueradedJsonForCreation(pJson, pMasqueradingVector, err);
    }

    static bool validateJsonForUpdate(const Json::Value &pJson, std::string &err)
    {
        if (!validateJsonForPassword(pJson, err))
            return false;
        return drogon_model::sqlite3::Users::validateJsonForUpdate(pJson, err);
    }

    static bool validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                                 const std::vector<std::string> &pMasqueradingVector,
                                                 std::string &err)
    {
        if (!validateJsonForPassword(pJson, err))
            return false;
        return drogon_model::sqlite3::Users::validateMasqueradedJsonForUpdate(pJson, pMasqueradingVector, err);
    }

    Json::Value toJson() const
    {
        auto result = drogon_model::sqlite3::Users::toJson();
        result.removeMember("password_hash");
        return result;
    }

    Json::Value toMasqueradedJson(const std::vector<std::string> &pMasqueradingVector) const
    {
        auto result = drogon_model::sqlite3::Users::toMasqueradedJson(pMasqueradingVector);
        result.removeMember(pMasqueradingVector[3]);
        return result;
    }

    /**
     * Checks whether user is enabled (enabled user - not banned user with set password).
     * @return True if user is enables else false.
     */
    bool isEnabled() noexcept;

    /**
     * Sets user's password.
     * @param pPassword User password.
     * @return True if password was set else false.
     */
    bool setPassword(const std::string &pPassword) noexcept;

    /**
     * Checks user's password.
     * @param pPassword Typed password.
     * @return True if typed password is correct else false.
     */
    [[nodiscard]] bool checkPassword(const std::string &pPassword) const noexcept;

private:
    friend Mapper<UsersExt>;

    static void updateJWT();

    static std::int64_t m_expiresIn;  // JWT duration
    static jwt::algorithm::hs256 *m_secretHash;      // JWT secret hash
};
