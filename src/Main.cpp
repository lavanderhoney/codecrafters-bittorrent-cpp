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
#include "lib/HTTPRequest.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

// Forward declarations
json decode_bencoded_value(const std::string& encoded_value, size_t& position);
void parse_metainfo(const vector<char>& buffer, bool f);
string bencode_json(const json& j);
json sort_json(const json& input_json);
vector<char> read_from_file(const string& file_path);
vector<string> get_hex_string(const json info_dict);
string url_encode_request(const string& tracker_url, const string& info_hash, const size_t& file_length);
void get_peers(const string& request_uri);

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

vector<char> read_from_file(const string& file_path){
    if(!fs::exists(file_path)) { throw runtime_error("File don't exist: " + file_path); }
    //get filesize
    size_t size = fs::file_size(file_path);
    
    // Open the file in binary mode using std::ifstream
    ifstream file(file_path, ios::binary);
    if (!file) { throw runtime_error("Error opening file: " + file_path); }

    //Create buffer vector to store the file contents
    vector<char> buffer (size);
    //read the file
    if (!file.read(buffer.data(), size)) { throw runtime_error("Error reading file: " + file_path); }
    return buffer;
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

vector<string> get_hex_string(const json info_dict){
    size_t pieces_length = info_dict["piece length"].get<size_t>();
    vector<uint8_t>pieces_hash = info_dict["pieces"].get<vector<uint8_t>>();

    // cout<<"pieces length: " << pieces_length << endl;
    // cout<< "pieces hash" <<endl;
    
    // cout<< pieces_hash.size() << endl;

    vector<string> hex_strings;
    for (size_t i = 0; i < pieces_hash.size(); i += 20)
    {
        vector<uint8_t>curr_hash(pieces_hash.begin()+i, pieces_hash.begin()+i+20);
        std::ostringstream oss;
        for (uint8_t byte : curr_hash) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        hex_strings.push_back(oss.str());
    }
    // cout<< hex_strings.size()<<endl;
    return hex_strings;
}

void parse_metainfo(const vector<char>& buffer, bool f){
    //convert buffer to string and return it
    string bencoded_meta_info = string(buffer.begin(), buffer.end());
    json metainfo_dict = decode_bencoded_value(bencoded_meta_info);

    json sorted_metainfo_dict = sort_json(metainfo_dict["info"]);
    string bencoded_info = bencode_json(sorted_metainfo_dict);

    vector<string> pieces_hash_hex = get_hex_string(sorted_metainfo_dict);

    SHA1 sha1;
    sha1.update(bencoded_info);
    string info_hash = sha1.final();

    if(f){
        cout << "Piece Length: " <<sorted_metainfo_dict["piece length"].get<size_t>() <<endl;
        cout << "Piece Hashes: " << endl;
        for (auto it:pieces_hash_hex){
            cout << it <<endl;
        }
        cout << "Info Hash: " << info_hash << endl;
        cout << "Tracker URL: " << metainfo_dict["announce"].get<string>() << endl;
        cout << "Length: " << metainfo_dict["info"]["length"] << endl;
    }else{
        string request_url = url_encode_request(metainfo_dict["announce"].get<string>(), info_hash, metainfo_dict["info"]["length"].get<size_t>());
        get_peers(request_url);
    }
}

string url_encode_request(const string& tracker_url, const string& info_hash, const size_t& file_length){
    string request_url;
    string result;
    result.reserve(info_hash.length() + info_hash.length() / 2);
    array<bool, 256> unreserved{};
    for (size_t i = '0'; i <= '9'; ++i)
            unreserved[i] = true;
    for (size_t i = 'A'; i <= 'Z'; ++i)
            unreserved[i] = true;
    for (size_t i = 'a'; i <= 'z'; ++i)
            unreserved[i] = true;
    unreserved['-'] = true;
    unreserved['_'] = true;
    unreserved['.'] = true;
    unreserved['~'] = true;
    for (size_t i = 0; i < info_hash.length(); i += 2)
    {
            std::string byte_str = info_hash.substr(i, 2);
            size_t byte_val = std::stoul(byte_str, nullptr, 16);
            if (unreserved[byte_val])
            {
                    result += static_cast<char>(byte_val);
            }
            else
            {
                    result += "%" + byte_str;
            }
    }
    string left = to_string(file_length);
    request_url = tracker_url + "?info_hash=" + result + "&peer_id=89605419386361446009&port=6881&uploaded=0&downloaded=0&left="+ left + "&compact=1";
    return request_url;
}

void get_peers(const string& request_uri){
    try {
        http::Request request{request_uri}; 
        const http::Response response = request.send("GET");

        string request_body = {response.body.begin(), response.body.end()};
       
        json response_dict = decode_bencoded_value(request_body);
        // cout << response_dict.at("peers") << endl;
        cout << response_dict.at("peers").is_array() << endl;  

        vector<size_t>peers;
        for(const auto& el : response_dict.at("peers")){
            cout << el << " ";
            peers.push_back(el);
        }
        for (size_t i = 0; i < peers.size(); i += 6){
            const string ip = to_string(peers[i]) + "." + to_string(peers[i + 1]) + "." +to_string(peers[i + 2]) + "." +to_string(peers[i + 3]);                                       
            const uint16_t port = (static_cast<uint16_t>(static_cast<unsigned char>(peers[i + 4]) << 8)) | static_cast<uint16_t>(static_cast<unsigned char>(peers[i + 5]));
            cout << ip << ":" << port << "\n";
        }
        //The last 2 bytes represent the port number, in big-endian order, i.e, MSByte first. So, the first byte has to be left shifted by 8, to make room for the 2nd byte to be added to it
        // Bitwise oring adds the LSByte
        //  example, 201 = 0xc9 in hexadecimal and 14 = 0x0e in hexadecimal are the port bytes. Then left shift 201 by 8 bits, then add 14 to that
        // When put together left to right, 0xc90e is 51470 ((16^0) x 14 + (16^1) x 0 + (16 ^2) x 9 + (16^3) x 12)
    } catch (const std::exception& e) {
        std::cerr << "Request failed, error: " << e.what() << endl;
    }

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
    } else if(command == "info" ){
        vector<char> metafile_contents = read_from_file(argv[2]);
        parse_metainfo(metafile_contents, true);
        
    }else if(command == "peers"){
         vector<char> metafile_contents = read_from_file(argv[2]);
        parse_metainfo(metafile_contents, false);
    }else {
        cerr << "unknown command: " << command << endl;
        return 1;
    }
    // vector<char> metafile_contents = read_from_file("sample.torrent");
    // parse_metainfo(metafile_contents);
    return 0;
}
