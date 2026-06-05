#include <boost/burl.hpp>

int
main()
{
    std::error_code ec = boost::burl::error::bad_redirect_response;
    if(!ec)
        throw;
}
