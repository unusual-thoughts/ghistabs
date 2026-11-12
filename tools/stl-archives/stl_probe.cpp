// Instantiates the standard library types that turn up in MSVC binaries, so that a /Zi build's PDB
// carries their full layouts. Nothing here runs: each global's definition is what puts its type,
// and the node, iterator and base types its constructor and destructor touch, in the PDB.
#include <any>
#include <array>
#include <atomic>
#include <bitset>
#include <chrono>
#include <complex>
#include <condition_variable>
#include <deque>
#include <exception>
#include <filesystem>
#include <forward_list>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <locale>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <typeinfo>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace probe {

std::string string_;
std::wstring wstring_;
std::u16string u16string_;
std::u32string u32string_;
std::string_view string_view_;
std::wstring_view wstring_view_;
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
std::forward_list<int> forward_list_int_;

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

std::unordered_map<int, int> unordered_map_int_int_;
std::unordered_map<int, void*> unordered_map_int_ptr_;
std::unordered_map<std::string, int> unordered_map_string_int_;
std::unordered_map<std::string, std::string> unordered_map_string_string_;
std::unordered_map<std::string, void*> unordered_map_string_ptr_;
std::unordered_set<int> unordered_set_int_;
std::unordered_set<std::string> unordered_set_string_;

std::deque<int> deque_int_;
std::deque<void*> deque_ptr_;
std::queue<int> queue_int_;
std::stack<int> stack_int_;
std::priority_queue<int> priority_queue_int_;

std::pair<int, int> pair_int_int_;
std::tuple<int, int, int> tuple_int_;
std::array<int, 4> array_int_;
std::bitset<32> bitset_32_;
std::optional<int> optional_int_;
std::variant<int, std::string> variant_int_string_;
std::any any_;
std::complex<double> complex_double_;

std::shared_ptr<void> shared_ptr_void_;
std::shared_ptr<int> shared_ptr_int_ = std::make_shared<int>();
std::weak_ptr<void> weak_ptr_void_;
std::unique_ptr<int> unique_ptr_int_;
std::unique_ptr<int[]> unique_ptr_array_;
std::function<void()> function_void_;
std::function<int(int)> function_int_int_;
std::reference_wrapper<int> reference_wrapper_int_{array_int_[0]};

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
std::istreambuf_iterator<char> istreambuf_iterator_;
std::ostreambuf_iterator<char> ostreambuf_iterator_{std::cout};

std::locale locale_;
const std::ctype<char>* ctype_char_ = &std::use_facet<std::ctype<char>>(locale_);
const std::ctype<wchar_t>* ctype_wchar_ = &std::use_facet<std::ctype<wchar_t>>(locale_);
const std::numpunct<char>* numpunct_char_ = &std::use_facet<std::numpunct<char>>(locale_);
const std::num_get<char>* num_get_char_ = &std::use_facet<std::num_get<char>>(locale_);
const std::num_put<char>* num_put_char_ = &std::use_facet<std::num_put<char>>(locale_);
const std::codecvt<char, char, std::mbstate_t>* codecvt_char_ =
    &std::use_facet<std::codecvt<char, char, std::mbstate_t>>(locale_);
const std::collate<char>* collate_char_ = &std::use_facet<std::collate<char>>(locale_);
const std::moneypunct<char>* moneypunct_char_ = &std::use_facet<std::moneypunct<char>>(locale_);
const std::time_get<char>* time_get_char_ = &std::use_facet<std::time_get<char>>(locale_);
const std::messages<char>* messages_char_ = &std::use_facet<std::messages<char>>(locale_);

std::exception exception_;
std::bad_alloc bad_alloc_;
std::bad_array_new_length bad_array_new_length_;
std::bad_cast bad_cast_;
std::bad_typeid bad_typeid_;
std::bad_function_call bad_function_call_;
std::bad_weak_ptr bad_weak_ptr_;
std::bad_optional_access bad_optional_access_;
std::bad_variant_access bad_variant_access_;
std::logic_error logic_error_{""};
std::domain_error domain_error_{""};
std::invalid_argument invalid_argument_{""};
std::length_error length_error_{""};
std::out_of_range out_of_range_{""};
std::runtime_error runtime_error_{""};
std::range_error range_error_{""};
std::overflow_error overflow_error_{""};
std::underflow_error underflow_error_{""};
std::system_error system_error_{std::error_code()};
std::ios_base::failure ios_failure_{""};
std::regex_error regex_error_{std::regex_constants::error_collate};
std::filesystem::filesystem_error filesystem_error_{"", std::error_code()};
std::exception_ptr exception_ptr_;
std::error_code error_code_;
std::error_condition error_condition_;

std::regex regex_;
std::wregex wregex_;
std::smatch smatch_;
std::cmatch cmatch_;

std::mutex mutex_;
std::recursive_mutex recursive_mutex_;
std::timed_mutex timed_mutex_;
std::shared_mutex shared_mutex_;
std::condition_variable condition_variable_;
std::condition_variable_any condition_variable_any_;
std::unique_lock<std::mutex> unique_lock_;
std::lock_guard<std::mutex> lock_guard_{mutex_};
std::thread thread_;
std::once_flag once_flag_;
std::atomic<int> atomic_int_;
std::atomic<void*> atomic_ptr_;
std::atomic_flag atomic_flag_;

std::chrono::system_clock::time_point system_time_point_;
std::chrono::steady_clock::time_point steady_time_point_;
std::chrono::milliseconds milliseconds_;
std::filesystem::path path_;
std::filesystem::directory_entry directory_entry_;
std::filesystem::directory_iterator directory_iterator_;

}  // namespace probe

int main() {
    return 0;
}
