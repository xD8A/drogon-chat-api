/**
 *
 *  Contacts.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "Contacts.h"
#include "Users.h"
#include "Users.h"
#include "Messages.h"
#include "ContactMessages.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon_model::sqlite3;

const std::string Contacts::Cols::_id = "id";
const std::string Contacts::Cols::_owner_id = "owner_id";
const std::string Contacts::Cols::_friend_id = "friend_id";
const std::string Contacts::Cols::_name = "name";
const std::string Contacts::primaryKeyName = "id";
const bool Contacts::hasPrimaryKey = true;
const std::string Contacts::tableName = "contacts";

const std::vector<typename Contacts::MetaData> Contacts::metaData_={
{"id","uint64_t","integer",8,1,1,0},
{"owner_id","uint64_t","integer",8,0,0,1},
{"friend_id","uint64_t","integer",8,0,0,1},
{"name","std::string","text",0,0,0,1}
};
const std::string &Contacts::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
Contacts::Contacts(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["id"].isNull())
        {
            id_=std::make_shared<uint64_t>(r["id"].as<uint64_t>());
        }
        if(!r["owner_id"].isNull())
        {
            ownerId_=std::make_shared<uint64_t>(r["owner_id"].as<uint64_t>());
        }
        if(!r["friend_id"].isNull())
        {
            friendId_=std::make_shared<uint64_t>(r["friend_id"].as<uint64_t>());
        }
        if(!r["name"].isNull())
        {
            name_=std::make_shared<std::string>(r["name"].as<std::string>());
        }
    }
    else
    {
        size_t offset = (size_t)indexOffset;
        if(offset + 4 > r.size())
        {
            LOG_FATAL << "Invalid SQL result for this model";
            return;
        }
        size_t index;
        index = offset + 0;
        if(!r[index].isNull())
        {
            id_=std::make_shared<uint64_t>(r[index].as<uint64_t>());
        }
        index = offset + 1;
        if(!r[index].isNull())
        {
            ownerId_=std::make_shared<uint64_t>(r[index].as<uint64_t>());
        }
        index = offset + 2;
        if(!r[index].isNull())
        {
            friendId_=std::make_shared<uint64_t>(r[index].as<uint64_t>());
        }
        index = offset + 3;
        if(!r[index].isNull())
        {
            name_=std::make_shared<std::string>(r[index].as<std::string>());
        }
    }

}

Contacts::Contacts(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 4)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        dirtyFlag_[0] = true;
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            id_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[0]].asUInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            ownerId_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[1]].asUInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            friendId_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[2]].asUInt64());
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            name_=std::make_shared<std::string>(pJson[pMasqueradingVector[3]].asString());

        }
    }
}

Contacts::Contacts(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("id"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["id"].isNull())
        {
            id_=std::make_shared<uint64_t>((uint64_t)pJson["id"].asUInt64());
        }
    }
    if(pJson.isMember("owner_id"))
    {
        dirtyFlag_[1]=true;
        if(!pJson["owner_id"].isNull())
        {
            ownerId_=std::make_shared<uint64_t>((uint64_t)pJson["owner_id"].asUInt64());
        }
    }
    if(pJson.isMember("friend_id"))
    {
        dirtyFlag_[2]=true;
        if(!pJson["friend_id"].isNull())
        {
            friendId_=std::make_shared<uint64_t>((uint64_t)pJson["friend_id"].asUInt64());
        }
    }
    if(pJson.isMember("name"))
    {
        dirtyFlag_[3]=true;
        if(!pJson["name"].isNull())
        {
            name_=std::make_shared<std::string>(pJson["name"].asString());
        }
    }
}

void Contacts::updateByMasqueradedJson(const Json::Value &pJson,
                                            const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 4)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            id_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[0]].asUInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            ownerId_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[1]].asUInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            friendId_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[2]].asUInt64());
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            name_=std::make_shared<std::string>(pJson[pMasqueradingVector[3]].asString());
        }
    }
}
                                                                    
void Contacts::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("id"))
    {
        if(!pJson["id"].isNull())
        {
            id_=std::make_shared<uint64_t>((uint64_t)pJson["id"].asUInt64());
        }
    }
    if(pJson.isMember("owner_id"))
    {
        dirtyFlag_[1] = true;
        if(!pJson["owner_id"].isNull())
        {
            ownerId_=std::make_shared<uint64_t>((uint64_t)pJson["owner_id"].asUInt64());
        }
    }
    if(pJson.isMember("friend_id"))
    {
        dirtyFlag_[2] = true;
        if(!pJson["friend_id"].isNull())
        {
            friendId_=std::make_shared<uint64_t>((uint64_t)pJson["friend_id"].asUInt64());
        }
    }
    if(pJson.isMember("name"))
    {
        dirtyFlag_[3] = true;
        if(!pJson["name"].isNull())
        {
            name_=std::make_shared<std::string>(pJson["name"].asString());
        }
    }
}

const uint64_t &Contacts::getValueOfId() const noexcept
{
    const static uint64_t defaultValue = uint64_t();
    if(id_)
        return *id_;
    return defaultValue;
}
const std::shared_ptr<uint64_t> &Contacts::getId() const noexcept
{
    return id_;
}
void Contacts::setId(const uint64_t &pId) noexcept
{
    id_ = std::make_shared<uint64_t>(pId);
    dirtyFlag_[0] = true;
}


void Contacts::setIdToNull() noexcept
{
    id_.reset();
    dirtyFlag_[0] = true;
}

const typename Contacts::PrimaryKeyType & Contacts::getPrimaryKey() const
{
    assert(id_);
    return *id_;
}

const uint64_t &Contacts::getValueOfOwnerId() const noexcept
{
    const static uint64_t defaultValue = uint64_t();
    if(ownerId_)
        return *ownerId_;
    return defaultValue;
}
const std::shared_ptr<uint64_t> &Contacts::getOwnerId() const noexcept
{
    return ownerId_;
}
void Contacts::setOwnerId(const uint64_t &pOwnerId) noexcept
{
    ownerId_ = std::make_shared<uint64_t>(pOwnerId);
    dirtyFlag_[1] = true;
}




const uint64_t &Contacts::getValueOfFriendId() const noexcept
{
    const static uint64_t defaultValue = uint64_t();
    if(friendId_)
        return *friendId_;
    return defaultValue;
}
const std::shared_ptr<uint64_t> &Contacts::getFriendId() const noexcept
{
    return friendId_;
}
void Contacts::setFriendId(const uint64_t &pFriendId) noexcept
{
    friendId_ = std::make_shared<uint64_t>(pFriendId);
    dirtyFlag_[2] = true;
}




const std::string &Contacts::getValueOfName() const noexcept
{
    const static std::string defaultValue = std::string();
    if(name_)
        return *name_;
    return defaultValue;
}
const std::shared_ptr<std::string> &Contacts::getName() const noexcept
{
    return name_;
}
void Contacts::setName(const std::string &pName) noexcept
{
    name_ = std::make_shared<std::string>(pName);
    dirtyFlag_[3] = true;
}
void Contacts::setName(std::string &&pName) noexcept
{
    name_ = std::make_shared<std::string>(std::move(pName));
    dirtyFlag_[3] = true;
}




void Contacts::updateId(const uint64_t id)
{
    id_ = std::make_shared<uint64_t>(id);
}

const std::vector<std::string> &Contacts::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "owner_id",
        "friend_id",
        "name"
    };
    return inCols;
}

void Contacts::outputArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getOwnerId())
        {
            binder << getValueOfOwnerId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getFriendId())
        {
            binder << getValueOfFriendId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getName())
        {
            binder << getValueOfName();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> Contacts::updateColumns() const
{
    std::vector<std::string> ret;
    if(dirtyFlag_[1])
    {
        ret.push_back(getColumnName(1));
    }
    if(dirtyFlag_[2])
    {
        ret.push_back(getColumnName(2));
    }
    if(dirtyFlag_[3])
    {
        ret.push_back(getColumnName(3));
    }
    return ret;
}

void Contacts::updateArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getOwnerId())
        {
            binder << getValueOfOwnerId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getFriendId())
        {
            binder << getValueOfFriendId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getName())
        {
            binder << getValueOfName();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value Contacts::toJson() const
{
    Json::Value ret;
    if(getId())
    {
        ret["id"]=(Json::UInt64)getValueOfId();
    }
    else
    {
        ret["id"]=Json::Value();
    }
    if(getOwnerId())
    {
        ret["owner_id"]=(Json::UInt64)getValueOfOwnerId();
    }
    else
    {
        ret["owner_id"]=Json::Value();
    }
    if(getFriendId())
    {
        ret["friend_id"]=(Json::UInt64)getValueOfFriendId();
    }
    else
    {
        ret["friend_id"]=Json::Value();
    }
    if(getName())
    {
        ret["name"]=getValueOfName();
    }
    else
    {
        ret["name"]=Json::Value();
    }
    return ret;
}

Json::Value Contacts::toMasqueradedJson(
    const std::vector<std::string> &pMasqueradingVector) const
{
    Json::Value ret;
    if(pMasqueradingVector.size() == 4)
    {
        if(!pMasqueradingVector[0].empty())
        {
            if(getId())
            {
                ret[pMasqueradingVector[0]]=(Json::UInt64)getValueOfId();
            }
            else
            {
                ret[pMasqueradingVector[0]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[1].empty())
        {
            if(getOwnerId())
            {
                ret[pMasqueradingVector[1]]=(Json::UInt64)getValueOfOwnerId();
            }
            else
            {
                ret[pMasqueradingVector[1]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[2].empty())
        {
            if(getFriendId())
            {
                ret[pMasqueradingVector[2]]=(Json::UInt64)getValueOfFriendId();
            }
            else
            {
                ret[pMasqueradingVector[2]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[3].empty())
        {
            if(getName())
            {
                ret[pMasqueradingVector[3]]=getValueOfName();
            }
            else
            {
                ret[pMasqueradingVector[3]]=Json::Value();
            }
        }
        return ret;
    }
    LOG_ERROR << "Masquerade failed";
    if(getId())
    {
        ret["id"]=(Json::UInt64)getValueOfId();
    }
    else
    {
        ret["id"]=Json::Value();
    }
    if(getOwnerId())
    {
        ret["owner_id"]=(Json::UInt64)getValueOfOwnerId();
    }
    else
    {
        ret["owner_id"]=Json::Value();
    }
    if(getFriendId())
    {
        ret["friend_id"]=(Json::UInt64)getValueOfFriendId();
    }
    else
    {
        ret["friend_id"]=Json::Value();
    }
    if(getName())
    {
        ret["name"]=getValueOfName();
    }
    else
    {
        ret["name"]=Json::Value();
    }
    return ret;
}

bool Contacts::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("id"))
    {
        if(!validJsonOfField(0, "id", pJson["id"], err, true))
            return false;
    }
    if(pJson.isMember("owner_id"))
    {
        if(!validJsonOfField(1, "owner_id", pJson["owner_id"], err, true))
            return false;
    }
    else
    {
        err="The owner_id column cannot be null";
        return false;
    }
    if(pJson.isMember("friend_id"))
    {
        if(!validJsonOfField(2, "friend_id", pJson["friend_id"], err, true))
            return false;
    }
    else
    {
        err="The friend_id column cannot be null";
        return false;
    }
    if(pJson.isMember("name"))
    {
        if(!validJsonOfField(3, "name", pJson["name"], err, true))
            return false;
    }
    else
    {
        err="The name column cannot be null";
        return false;
    }
    return true;
}
bool Contacts::validateMasqueradedJsonForCreation(const Json::Value &pJson,
                                                  const std::vector<std::string> &pMasqueradingVector,
                                                  std::string &err)
{
    if(pMasqueradingVector.size() != 4)
    {
        err = "Bad masquerading vector";
        return false;
    }
    try {
      if(!pMasqueradingVector[0].empty())
      {
          if(pJson.isMember(pMasqueradingVector[0]))
          {
              if(!validJsonOfField(0, pMasqueradingVector[0], pJson[pMasqueradingVector[0]], err, true))
                  return false;
          }
      }
      if(!pMasqueradingVector[1].empty())
      {
          if(pJson.isMember(pMasqueradingVector[1]))
          {
              if(!validJsonOfField(1, pMasqueradingVector[1], pJson[pMasqueradingVector[1]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[1] + " column cannot be null";
            return false;
        }
      }
      if(!pMasqueradingVector[2].empty())
      {
          if(pJson.isMember(pMasqueradingVector[2]))
          {
              if(!validJsonOfField(2, pMasqueradingVector[2], pJson[pMasqueradingVector[2]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[2] + " column cannot be null";
            return false;
        }
      }
      if(!pMasqueradingVector[3].empty())
      {
          if(pJson.isMember(pMasqueradingVector[3]))
          {
              if(!validJsonOfField(3, pMasqueradingVector[3], pJson[pMasqueradingVector[3]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[3] + " column cannot be null";
            return false;
        }
      }
    }
    catch(const Json::LogicError &e) 
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Contacts::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("id"))
    {
        if(!validJsonOfField(0, "id", pJson["id"], err, false))
            return false;
    }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
    if(pJson.isMember("owner_id"))
    {
        if(!validJsonOfField(1, "owner_id", pJson["owner_id"], err, false))
            return false;
    }
    if(pJson.isMember("friend_id"))
    {
        if(!validJsonOfField(2, "friend_id", pJson["friend_id"], err, false))
            return false;
    }
    if(pJson.isMember("name"))
    {
        if(!validJsonOfField(3, "name", pJson["name"], err, false))
            return false;
    }
    return true;
}
bool Contacts::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                                const std::vector<std::string> &pMasqueradingVector,
                                                std::string &err)
{
    if(pMasqueradingVector.size() != 4)
    {
        err = "Bad masquerading vector";
        return false;
    }
    try {
      if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
      {
          if(!validJsonOfField(0, pMasqueradingVector[0], pJson[pMasqueradingVector[0]], err, false))
              return false;
      }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
      if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
      {
          if(!validJsonOfField(1, pMasqueradingVector[1], pJson[pMasqueradingVector[1]], err, false))
              return false;
      }
      if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
      {
          if(!validJsonOfField(2, pMasqueradingVector[2], pJson[pMasqueradingVector[2]], err, false))
              return false;
      }
      if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
      {
          if(!validJsonOfField(3, pMasqueradingVector[3], pJson[pMasqueradingVector[3]], err, false))
              return false;
      }
    }
    catch(const Json::LogicError &e) 
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Contacts::validJsonOfField(size_t index,
                                const std::string &fieldName,
                                const Json::Value &pJson, 
                                std::string &err, 
                                bool isForCreation)
{
    switch(index)
    {
        case 0:
            if(isForCreation)
            {
                err="The automatic primary key cannot be set";
                return false;
            }        
            if(pJson.isNull())
            {
                return true;
            }
            if(!pJson.isUInt64())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 1:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isUInt64())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 2:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isUInt64())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 3:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isString())
            {
                err="Type error in the "+fieldName+" field";
                return false;                
            }
            break;
     
        default:
            err="Internal error in the server";
            return false;
            break;
    }
    return true;
}
void Contacts::getOwner(const DbClientPtr &clientPtr, 
                        const std::function<void(Users)> &rcb,
                        const ExceptionCallback &ecb) const
{
    const static std::string sql = "select * from users where id = ?";
    *clientPtr << sql
               << *ownerId_ 
               >> [rcb = std::move(rcb), ecb](const Result &r){
                    if (r.size() == 0)
                    {
                        ecb(UnexpectedRows("0 rows found"));
                    }
                    else if (r.size() > 1)
                    {
                        ecb(UnexpectedRows("Found more than one row"));
                    }
                    else
                    {
                        rcb(Users(r[0]));
                    }
               }
               >> ecb;
}
void Contacts::getFriend(const DbClientPtr &clientPtr, 
                         const std::function<void(Users)> &rcb,
                         const ExceptionCallback &ecb) const
{
    const static std::string sql = "select * from users where id = ?";
    *clientPtr << sql
               << *friendId_ 
               >> [rcb = std::move(rcb), ecb](const Result &r){
                    if (r.size() == 0)
                    {
                        ecb(UnexpectedRows("0 rows found"));
                    }
                    else if (r.size() > 1)
                    {
                        ecb(UnexpectedRows("Found more than one row"));
                    }
                    else
                    {
                        rcb(Users(r[0]));
                    }
               }
               >> ecb;
}
void Contacts::getMessages(const DbClientPtr &clientPtr, 
                           const std::function<void(std::vector<std::pair<Messages,ContactMessages>>)> &rcb,
                           const ExceptionCallback &ecb) const
{
    const static std::string sql = "select * from messages,contact_messages where contact_messages.contact_id = ? and contact_messages.message_id = messages.id";
    *clientPtr << sql
               << *id_ 
               >> [rcb = std::move(rcb)](const Result &r){
                   std::vector<std::pair<Messages,ContactMessages>> ret;
                   ret.reserve(ret.size());
                   for (auto const &row : r)
                   {
                       ret.emplace_back(std::pair<Messages,ContactMessages>(
                           Messages(row),ContactMessages(row,Messages::getColumnNumber())));
                   }
                   rcb(ret);
               }
               >> ecb;
}
