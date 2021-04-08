/**
 *
 *  Messages.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "Messages.h"
#include "Users.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon_model::sqlite3;

const std::string Messages::Cols::_id = "id";
const std::string Messages::Cols::_author_id = "author_id";
const std::string Messages::Cols::_text = "text";
const std::string Messages::Cols::_created_at = "created_at";
const std::string Messages::primaryKeyName = "id";
const bool Messages::hasPrimaryKey = true;
const std::string Messages::tableName = "messages";

const std::vector<typename Messages::MetaData> Messages::metaData_={
{"id","uint64_t","integer",8,1,1,0},
{"author_id","uint64_t","integer",8,0,0,0},
{"text","std::string","text",0,0,0,1},
{"created_at","uint64_t","integer",8,0,0,1}
};
const std::string &Messages::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
Messages::Messages(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["id"].isNull())
        {
            id_=std::make_shared<uint64_t>(r["id"].as<uint64_t>());
        }
        if(!r["author_id"].isNull())
        {
            authorId_=std::make_shared<uint64_t>(r["author_id"].as<uint64_t>());
        }
        if(!r["text"].isNull())
        {
            text_=std::make_shared<std::string>(r["text"].as<std::string>());
        }
        if(!r["created_at"].isNull())
        {
            createdAt_=std::make_shared<uint64_t>(r["created_at"].as<uint64_t>());
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
            authorId_=std::make_shared<uint64_t>(r[index].as<uint64_t>());
        }
        index = offset + 2;
        if(!r[index].isNull())
        {
            text_=std::make_shared<std::string>(r[index].as<std::string>());
        }
        index = offset + 3;
        if(!r[index].isNull())
        {
            createdAt_=std::make_shared<uint64_t>(r[index].as<uint64_t>());
        }
    }

}

Messages::Messages(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
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
            authorId_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[1]].asUInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            text_=std::make_shared<std::string>(pJson[pMasqueradingVector[2]].asString());

        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            createdAt_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[3]].asUInt64());
        }
    }
}

Messages::Messages(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("id"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["id"].isNull())
        {
            id_=std::make_shared<uint64_t>((uint64_t)pJson["id"].asUInt64());
        }
    }
    if(pJson.isMember("author_id"))
    {
        dirtyFlag_[1]=true;
        if(!pJson["author_id"].isNull())
        {
            authorId_=std::make_shared<uint64_t>((uint64_t)pJson["author_id"].asUInt64());
        }
    }
    if(pJson.isMember("text"))
    {
        dirtyFlag_[2]=true;
        if(!pJson["text"].isNull())
        {
            text_=std::make_shared<std::string>(pJson["text"].asString());
        }
    }
    if(pJson.isMember("created_at"))
    {
        dirtyFlag_[3]=true;
        if(!pJson["created_at"].isNull())
        {
            createdAt_=std::make_shared<uint64_t>((uint64_t)pJson["created_at"].asUInt64());
        }
    }
}

void Messages::updateByMasqueradedJson(const Json::Value &pJson,
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
            authorId_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[1]].asUInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            text_=std::make_shared<std::string>(pJson[pMasqueradingVector[2]].asString());
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            createdAt_=std::make_shared<uint64_t>((uint64_t)pJson[pMasqueradingVector[3]].asUInt64());
        }
    }
}
                                                                    
void Messages::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("id"))
    {
        if(!pJson["id"].isNull())
        {
            id_=std::make_shared<uint64_t>((uint64_t)pJson["id"].asUInt64());
        }
    }
    if(pJson.isMember("author_id"))
    {
        dirtyFlag_[1] = true;
        if(!pJson["author_id"].isNull())
        {
            authorId_=std::make_shared<uint64_t>((uint64_t)pJson["author_id"].asUInt64());
        }
    }
    if(pJson.isMember("text"))
    {
        dirtyFlag_[2] = true;
        if(!pJson["text"].isNull())
        {
            text_=std::make_shared<std::string>(pJson["text"].asString());
        }
    }
    if(pJson.isMember("created_at"))
    {
        dirtyFlag_[3] = true;
        if(!pJson["created_at"].isNull())
        {
            createdAt_=std::make_shared<uint64_t>((uint64_t)pJson["created_at"].asUInt64());
        }
    }
}

const uint64_t &Messages::getValueOfId() const noexcept
{
    const static uint64_t defaultValue = uint64_t();
    if(id_)
        return *id_;
    return defaultValue;
}
const std::shared_ptr<uint64_t> &Messages::getId() const noexcept
{
    return id_;
}
void Messages::setId(const uint64_t &pId) noexcept
{
    id_ = std::make_shared<uint64_t>(pId);
    dirtyFlag_[0] = true;
}


void Messages::setIdToNull() noexcept
{
    id_.reset();
    dirtyFlag_[0] = true;
}

const typename Messages::PrimaryKeyType & Messages::getPrimaryKey() const
{
    assert(id_);
    return *id_;
}

const uint64_t &Messages::getValueOfAuthorId() const noexcept
{
    const static uint64_t defaultValue = uint64_t();
    if(authorId_)
        return *authorId_;
    return defaultValue;
}
const std::shared_ptr<uint64_t> &Messages::getAuthorId() const noexcept
{
    return authorId_;
}
void Messages::setAuthorId(const uint64_t &pAuthorId) noexcept
{
    authorId_ = std::make_shared<uint64_t>(pAuthorId);
    dirtyFlag_[1] = true;
}


void Messages::setAuthorIdToNull() noexcept
{
    authorId_.reset();
    dirtyFlag_[1] = true;
}


const std::string &Messages::getValueOfText() const noexcept
{
    const static std::string defaultValue = std::string();
    if(text_)
        return *text_;
    return defaultValue;
}
const std::shared_ptr<std::string> &Messages::getText() const noexcept
{
    return text_;
}
void Messages::setText(const std::string &pText) noexcept
{
    text_ = std::make_shared<std::string>(pText);
    dirtyFlag_[2] = true;
}
void Messages::setText(std::string &&pText) noexcept
{
    text_ = std::make_shared<std::string>(std::move(pText));
    dirtyFlag_[2] = true;
}




const uint64_t &Messages::getValueOfCreatedAt() const noexcept
{
    const static uint64_t defaultValue = uint64_t();
    if(createdAt_)
        return *createdAt_;
    return defaultValue;
}
const std::shared_ptr<uint64_t> &Messages::getCreatedAt() const noexcept
{
    return createdAt_;
}
void Messages::setCreatedAt(const uint64_t &pCreatedAt) noexcept
{
    createdAt_ = std::make_shared<uint64_t>(pCreatedAt);
    dirtyFlag_[3] = true;
}




void Messages::updateId(const uint64_t id)
{
    id_ = std::make_shared<uint64_t>(id);
}

const std::vector<std::string> &Messages::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "author_id",
        "text",
        "created_at"
    };
    return inCols;
}

void Messages::outputArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getAuthorId())
        {
            binder << getValueOfAuthorId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getText())
        {
            binder << getValueOfText();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getCreatedAt())
        {
            binder << getValueOfCreatedAt();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> Messages::updateColumns() const
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

void Messages::updateArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getAuthorId())
        {
            binder << getValueOfAuthorId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getText())
        {
            binder << getValueOfText();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getCreatedAt())
        {
            binder << getValueOfCreatedAt();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value Messages::toJson() const
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
    if(getAuthorId())
    {
        ret["author_id"]=(Json::UInt64)getValueOfAuthorId();
    }
    else
    {
        ret["author_id"]=Json::Value();
    }
    if(getText())
    {
        ret["text"]=getValueOfText();
    }
    else
    {
        ret["text"]=Json::Value();
    }
    if(getCreatedAt())
    {
        ret["created_at"]=(Json::UInt64)getValueOfCreatedAt();
    }
    else
    {
        ret["created_at"]=Json::Value();
    }
    return ret;
}

Json::Value Messages::toMasqueradedJson(
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
            if(getAuthorId())
            {
                ret[pMasqueradingVector[1]]=(Json::UInt64)getValueOfAuthorId();
            }
            else
            {
                ret[pMasqueradingVector[1]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[2].empty())
        {
            if(getText())
            {
                ret[pMasqueradingVector[2]]=getValueOfText();
            }
            else
            {
                ret[pMasqueradingVector[2]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[3].empty())
        {
            if(getCreatedAt())
            {
                ret[pMasqueradingVector[3]]=(Json::UInt64)getValueOfCreatedAt();
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
    if(getAuthorId())
    {
        ret["author_id"]=(Json::UInt64)getValueOfAuthorId();
    }
    else
    {
        ret["author_id"]=Json::Value();
    }
    if(getText())
    {
        ret["text"]=getValueOfText();
    }
    else
    {
        ret["text"]=Json::Value();
    }
    if(getCreatedAt())
    {
        ret["created_at"]=(Json::UInt64)getValueOfCreatedAt();
    }
    else
    {
        ret["created_at"]=Json::Value();
    }
    return ret;
}

bool Messages::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("id"))
    {
        if(!validJsonOfField(0, "id", pJson["id"], err, true))
            return false;
    }
    if(pJson.isMember("author_id"))
    {
        if(!validJsonOfField(1, "author_id", pJson["author_id"], err, true))
            return false;
    }
    if(pJson.isMember("text"))
    {
        if(!validJsonOfField(2, "text", pJson["text"], err, true))
            return false;
    }
    else
    {
        err="The text column cannot be null";
        return false;
    }
    if(pJson.isMember("created_at"))
    {
        if(!validJsonOfField(3, "created_at", pJson["created_at"], err, true))
            return false;
    }
    else
    {
        err="The created_at column cannot be null";
        return false;
    }
    return true;
}
bool Messages::validateMasqueradedJsonForCreation(const Json::Value &pJson,
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
bool Messages::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
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
    if(pJson.isMember("author_id"))
    {
        if(!validJsonOfField(1, "author_id", pJson["author_id"], err, false))
            return false;
    }
    if(pJson.isMember("text"))
    {
        if(!validJsonOfField(2, "text", pJson["text"], err, false))
            return false;
    }
    if(pJson.isMember("created_at"))
    {
        if(!validJsonOfField(3, "created_at", pJson["created_at"], err, false))
            return false;
    }
    return true;
}
bool Messages::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
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
bool Messages::validJsonOfField(size_t index,
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
                return true;
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
            if(!pJson.isString())
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
            if(!pJson.isUInt64())
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
void Messages::getAuthor(const DbClientPtr &clientPtr, 
                         const std::function<void(Users)> &rcb,
                         const ExceptionCallback &ecb) const
{
    const static std::string sql = "select * from users where author_id = ?";
    *clientPtr << sql
               << *id_ 
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
