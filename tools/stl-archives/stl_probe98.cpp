// The probe for the C++98 libstdc++ of gcc 3.3 (libstdc++.so.5), which stl_probe.cpp's C++17
// is beyond: it instantiates the library's types so that a -g build's debug info carries their full
// layouts. Nothing here runs.
#include <bitset>
#include <complex>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <list>
#include <locale>
#include <map>
#include <memory>
#include <new>
#include <queue>
#include <set>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <strstream>
#include <typeinfo>
#include <utility>
#include <valarray>
#include <vector>
#include <ext/hash_map>
#include <ext/hash_set>
#include <ext/rope>
#include <ext/slist>

namespace probe {

std::string string_;
std::wstring wstring_;
std::string::iterator string_iterator_;
std::string::const_iterator string_const_iterator_;

std::vector<int> vector_int_;
std::vector<void*> vector_ptr_;
std::vector<std::string> vector_string_;
std::vector<bool> vector_bool_;
std::vector<int>::iterator vector_iterator_;
std::vector<int>::const_iterator vector_const_iterator_;

std::list<int> list_int_;
std::list<void*> list_ptr_;
std::list<std::string> list_string_;
std::list<int>::iterator list_iterator_;

std::map<int, int> map_int_int_;
std::map<int, void*> map_int_ptr_;
std::map<std::string, int> map_string_int_;
std::map<std::string, std::string> map_string_string_;
std::map<std::string, void*> map_string_ptr_;
std::multimap<int, int> multimap_int_int_;
std::map<int, int>::iterator map_iterator_;
std::set<int> set_int_;
std::set<void*> set_ptr_;
std::set<std::string> set_string_;
std::multiset<int> multiset_int_;

__gnu_cxx::hash_map<int, int> hash_map_int_int_;
__gnu_cxx::hash_map<int, void*> hash_map_int_ptr_;
__gnu_cxx::hash_set<int> hash_set_int_;
__gnu_cxx::slist<int> slist_int_;
__gnu_cxx::crope crope_;

std::deque<int> deque_int_;
std::deque<void*> deque_ptr_;
std::queue<int> queue_int_;
std::stack<int> stack_int_;
std::priority_queue<int> priority_queue_int_;

std::pair<int, int> pair_int_int_;
std::bitset<32> bitset_32_;
std::complex<double> complex_double_;
std::valarray<double> valarray_double_;
std::auto_ptr<int> auto_ptr_int_;

std::ios_base::Init ios_init_;
std::streambuf* streambuf_ = std::cout.rdbuf();
std::filebuf filebuf_;
std::stringbuf stringbuf_;
std::ifstream ifstream_;
std::ofstream ofstream_;
std::fstream fstream_;
std::istringstream istringstream_;
std::ostringstream ostringstream_;
std::stringstream stringstream_;
std::wfilebuf wfilebuf_;
std::wstringbuf wstringbuf_;
std::wifstream wifstream_;
std::wofstream wofstream_;
std::wfstream wfstream_;
std::wistringstream wistringstream_;
std::wostringstream wostringstream_;
std::wstringstream wstringstream_;
std::strstreambuf strstreambuf_;
std::istrstream istrstream_("");
std::ostrstream ostrstream_;
std::strstream strstream_;
std::istreambuf_iterator<char> istreambuf_iterator_;
std::ostreambuf_iterator<char> ostreambuf_iterator_(std::cout);

std::locale locale_;
const std::ctype<char>* ctype_char_ = &std::use_facet<std::ctype<char> >(locale_);
const std::ctype<wchar_t>* ctype_wchar_ = &std::use_facet<std::ctype<wchar_t> >(locale_);
const std::numpunct<char>* numpunct_char_ = &std::use_facet<std::numpunct<char> >(locale_);
const std::num_get<char>* num_get_char_ = &std::use_facet<std::num_get<char> >(locale_);
const std::num_put<char>* num_put_char_ = &std::use_facet<std::num_put<char> >(locale_);
const std::codecvt<char, char, std::mbstate_t>* codecvt_char_ =
    &std::use_facet<std::codecvt<char, char, std::mbstate_t> >(locale_);
const std::collate<char>* collate_char_ = &std::use_facet<std::collate<char> >(locale_);
const std::moneypunct<char>* moneypunct_char_ = &std::use_facet<std::moneypunct<char> >(locale_);
const std::money_get<char>* money_get_char_ = &std::use_facet<std::money_get<char> >(locale_);
const std::money_put<char>* money_put_char_ = &std::use_facet<std::money_put<char> >(locale_);
const std::time_get<char>* time_get_char_ = &std::use_facet<std::time_get<char> >(locale_);
const std::time_put<char>* time_put_char_ = &std::use_facet<std::time_put<char> >(locale_);
const std::messages<char>* messages_char_ = &std::use_facet<std::messages<char> >(locale_);

std::exception exception_;
std::bad_exception bad_exception_;
std::bad_alloc bad_alloc_;
std::bad_cast bad_cast_;
std::bad_typeid bad_typeid_;
std::logic_error logic_error_("");
std::domain_error domain_error_("");
std::invalid_argument invalid_argument_("");
std::length_error length_error_("");
std::out_of_range out_of_range_("");
std::runtime_error runtime_error_("");
std::range_error range_error_("");
std::overflow_error overflow_error_("");
std::underflow_error underflow_error_("");
std::ios_base::failure ios_failure_("");

// A program's own classes deriving from the library's, as in stl_probe.cpp; no part of the archives.
struct ProbeError : std::runtime_error {
    explicit ProbeError(int code) : std::runtime_error("probe"), code(code) {}
    int code;
};

class CountingBuf : public std::streambuf {
public:
    CountingBuf() : written(0) {}
    std::size_t written;

protected:
    int_type overflow(int_type c) {
        ++written;
        return c;
    }
};

ProbeError probe_error_(1);
CountingBuf counting_buf_;

}  // namespace probe

int main() {
    return 0;
}
