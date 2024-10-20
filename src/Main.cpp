#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <typeinfo>
#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

// Forward declarations
json decode_bencoded_value(const std::string& encoded_value, size_t& position);
void parse_metainfo(const std::string& filePath);
string bencode_json(const json& j);
json sort_json(const json& input_json);

json decode_bencoded_string(const string& encoded_string, size_t& idx){
    size_t length_prefix = encoded_string.find(':', idx);
    if (length_prefix != string::npos) {
        string string_size_str = encoded_string.substr(idx, length_prefix - idx);
        int64_t string_size_int = atoll(string_size_str.c_str());

        idx = length_prefix + 1; // Move idx to the start of the actual string
        string str = encoded_string.substr(idx, string_size_int);
        idx += string_size_int; // Update idx to the end of the string

        // // Check if the string contains non-UTF-8 characters
        vector<uint8_t> byte_vector;
        for (char ch : str) {
            if (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) > 0x7E) { // Indicates possible binary data
                vector<uint8_t> byte_vector(str.begin(), str.end());
                return json(byte_vector);
            }
        }
        
        return json(str);
    } else {
        throw runtime_error("Invalid encoded value: " + encoded_string);
    }
}

json decode_bencoded_integer(const string& encoded_string, size_t& idx){
    idx++; //skip 'i'
    size_t end = encoded_string.find('e', idx);
    if (end == string::npos) {
        throw invalid_argument("Invalid bencoded integer");
    }
    string int_string = encoded_string.substr(idx, end-idx);
    
    int64_t decoded_int = atoll(int_string.c_str());
    idx = end+1; //move past 'e' for the next encoded data type
    return json(decoded_int);
}

json decode_bencoded_list(const string& encoded_string, size_t& idx){
    idx++;
    json list = json::array();

    while (idx < encoded_string.size() && encoded_string[idx]!='e'){
        list.push_back(decode_bencoded_value(encoded_string, idx));
    }
    if (idx >= encoded_string.size() || encoded_string[idx] != 'e') {
        throw runtime_error("Invalid bencoded list: missing 'e'");
    }
    idx++;
    // cout << list <<endl;
    return list;
}

json decode_bencoded_dict(const string& encoded_string, size_t& idx) {
    idx++; // Skip the 'd'
    json dict = json::object();

    while (encoded_string[idx] != 'e') {
        // Decode the key (which is always a bencoded string)
        json key = decode_bencoded_string(encoded_string, idx);

        if (!key.is_string()) {
            throw runtime_error("Invalid dictionary key type: " + key.dump());
        }
        // Decode the corresponding value
        json value = decode_bencoded_value(encoded_string, idx);

        // Add the key-value pair to the dictionary
        dict[key.get<string>()] = value;
    }

    idx++; // Move past 'e' for the next encoded data type
    return dict;
}

json decode_bencoded_value(const string& encoded_value, size_t& idx) {
    if (isdigit(encoded_value[idx])) {
        return decode_bencoded_string(encoded_value, idx);
    } else if(encoded_value[idx]=='i'){
        return decode_bencoded_integer(encoded_value, idx);
    }else if(encoded_value[idx]=='l'){
        return decode_bencoded_list(encoded_value, idx);
    }else if(encoded_value[idx]=='d'){
        return decode_bencoded_dict(encoded_value, idx);
    }else {
        throw runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

//operator overlaoding for calling in the main() functions
json decode_bencoded_value(const string& encoded_value) {
    size_t idx = 0;
    return decode_bencoded_value(encoded_value, idx);
}

void parse_metainfo(const string& filePath){
    if(!fs::exists(filePath)) { throw runtime_error("File don't exist: " + filePath); }
    //get filesize
    size_t size = fs::file_size(filePath);
    
    // Open the file in binary mode using std::ifstream
    ifstream file(filePath, ios::binary);
    if (!file) { throw runtime_error("Error opening file: " + filePath); }

    //Create buffer vector to store the file contents
    vector<char> buffer (size);
    //read the file
    if (!file.read(buffer.data(), size)) { throw runtime_error("Error reading file: " + filePath); }

    //convert buffer to string and return it
    string bencoded_meta_info = string(buffer.begin(), buffer.end());
    json metainfo_dict = decode_bencoded_value(bencoded_meta_info);

    json sorted_metainfo_dict = sort_json(metainfo_dict["info"]);
    string bencoded_info = bencode_json(sorted_metainfo_dict);

    SHA1 sha1;
    sha1.update(bencoded_info);
    string info_hash = sha1.final();

    cout << "Info Hash: " << info_hash << endl;
    cout << "Tracker URL: " << metainfo_dict["announce"].get<string>() << endl;
    cout << "Length: " << metainfo_dict["info"]["length"] << endl;
}
json sort_json(const json& input_json) {
    // Using std::map will sort the keys automatically.
    map<string, json> sorted_map;

    for (const auto it : input_json.items()) {
        sorted_map[it.key()] = it.value();
    }
    json sorted_json(sorted_map);
    return sorted_json;
}

string bencode_json(const json& j){
    ostringstream os;   
    if (j.is_object()){
        os << 'd';
        for(auto item : j.items()){
            os << item.key().size() << ':' << item.key() << bencode_json(item.value());
        }
        os << 'e';
    }else if (j.is_array() && j[0].is_number_unsigned()) {
        // Handle byte arrays.
        const auto& byte_array = j.get<std::vector<uint8_t>>();
        os << byte_array.size() << ':';
        for (uint8_t byte : byte_array) {
            os << static_cast<unsigned char>(byte);
        }
    }else if(j.is_array()){
        os << 'l';
        for(const json& el  : j){
            os << bencode_json(el);
        }
        os << 'e';
    }else if(j.is_number_integer()){
        os << 'i' << j.get<int>() << 'e';
    }else if(j.is_string()){
        const string value = j.get<string>();
        os << value.size() << ':' << value;
    }
    return os.str();
}


int main(int argc, char* argv[]) {
    // Flush after every cout / cerr
    cout << unitbuf;
    cerr << unitbuf;

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " decode <encoded_value>" << endl;
        return 1;
    }

    string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            cerr << "Usage: " << argv[0] << " decode <encoded_value>" << endl;
            return 1;
        }
    
        string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value);
        cout << decoded_value.dump() << endl;
    } else if(command == "info"){

        parse_metainfo(argv[2]);
        
    }
    else {
        cerr << "unknown command: " << command << endl;
        return 1;
    }
    return 0;
}