#include <boost/burl.hpp>

int main() {
  std::error_code ec = boost::burl::error::success;
  if (ec)
    throw;
}
