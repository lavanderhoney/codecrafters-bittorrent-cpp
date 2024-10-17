#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <stdexcept>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

// Forward declarations
json decode_bencoded_value(const std::string& encoded_value, size_t& position);
json readFile(const std::string& filePath);

json decode_bencoded_string(const string& encoded_string, size_t& idx){
    size_t length_prefix = encoded_string.find(':', idx);
    if (length_prefix != string::npos) {
        string string_size_str = encoded_string.substr(idx, length_prefix - idx);
        int64_t string_size_int = atoll(string_size_str.c_str());

        idx = length_prefix + 1; // Move idx to the start of the actual string
        string str = encoded_string.substr(idx, string_size_int);
        idx += string_size_int; // Update idx to the end of the string

        // idx = length_prefix + 1 + string_size_int; // Update idx
        // string str = encoded_string.substr(length_prefix + 1, string_size_int);
        // Check if the string contains non-UTF-8 characters
        for (char ch : str) {
            if (ch < 0) { // Indicates possible binary data
                std::vector<uint8_t> byte_array(str.begin(), str.end());
                return json(byte_array);
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

json readFile(const string& filePath){
    if(!fs::exists(filePath)) { throw runtime_error("File don't exist: " + filePath); }
    //get filesize
    uint64_t size = fs::file_size(filePath);
    
    // Open the file in binary mode using std::ifstream
    ifstream file(filePath, ios::binary);
    if (!file) { throw runtime_error("Error opening file: " + filePath); }

    //Create buffer vector to store the file contents
    vector<char> buffer (size);

    //read the file
    if (!file.read(buffer.data(), size)) { throw runtime_error("Error reading file: " + filePath); }

    //convert buffer to string and return it
    string bencoded_meta_info = string(buffer.begin(), buffer.end());
    return decode_bencoded_value(bencoded_meta_info);
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
        json filecontent = readFile(argv[0]);
        for(const auto& item: filecontent.items()){
            cout<<item.key()<< item.value() << endl;
        }
        cout << "Tracker URL: " << filecontent["announce"] << endl;
        cout << "Length: " << filecontent["info"]["length"] << endl;
    }
    else {
        cerr << "unknown command: " << command << endl;
        return 1;
    }
    return 0;
        
    // json filecontent = readFile("sample.torrent");
//     cout << filecontent << endl;
   
//    for(const auto& item: filecontent.items()){
//         cout<<item.key()<< item.value() << endl;
//    }
//    cout << filecontent["info"]["length"] << endl;
    // return 0;
}
