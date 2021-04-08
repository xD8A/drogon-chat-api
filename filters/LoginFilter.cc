/**
 *
 *  LoginFilter.cc
 *
 */

#include "LoginFilter.h"
#include "UsersExt.h"

using namespace drogon;

void LoginFilter::doFilter(const HttpRequestPtr &req,
                           FilterCallback &&fcb,
                           FilterChainCallback &&fccb)
{
    std::string auth = req->getHeader("Authorization");
    if (auth.rfind("Bearer", 0) == 0) {
        auto token = auth.substr(6);
        auto userId = UsersExt::extractUserId(token);
        if (userId.has_value()) {
            //Passed
            LOG_DEBUG << "Bearer authorization passed";
            fccb();
            return;
        }
        else {
            LOG_WARN << "Bearer authorization failed";
        }
    }
    else {
        LOG_WARN << "Unsupported authorization type";
    }
    //Check failed
    auto res = drogon::HttpResponse::newHttpResponse();
    res->setStatusCode(k401Unauthorized);
    fcb(res);
}
