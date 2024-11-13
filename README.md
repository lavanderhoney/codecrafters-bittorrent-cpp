[![progress-banner](https://backend.codecrafters.io/progress/bittorrent/dfb802be-f056-4f8c-80f6-090bb44c7c6d)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

This is my C++ solutions to the
["Build Your Own BitTorrent" Challenge](https://app.codecrafters.io/courses/bittorrent/overview).

In this challenge, I built a BitTorrent client that's capable of parsing a
.torrent file and downloading a file from a peer. I also learnt 
about how torrent files are structured, HTTP trackers, BitTorrent’s Peer
Protocol, pipelining and more.

**Note**: Head over to
[codecrafters.io](https://codecrafters.io) to try the challenge.

# Running the code
To test this client, you will have to seed a file using a thrid-party app like uTorrent, then get its `.torrent ` metafile from that app. Put the metafile in the `src` directory to execute the commands
## Building the project
1. Clone the repository:
   ```sh
   git clone https://github.com/lavanderhoney/codecrafters-bittorrent-cpp.git
2. Navigate to the project directory:
`cd codecrafters-bittorrent-cpp`

3. Build the project using cmake:
`cmake .
make
`

## Commands Implemented
The client supports several commands:
- decode: Decodes bencoded data
 ` ./your_bittorrent decode <encoded_value>`

- info: Displays torrent metadata information
  `./your_bittorrent info <torrent_file>`
  
- peers: Lists available peers
`./your_bittorrent peers <torrent_file>`

- handshake: Tests peer handshake protocol
`./your_bittorrent handshake <torrent_file> <peer_ip>:<peer_port>`
  
- download_piece: Downloads specific pieces
`./your_bittorrent download_piece -o <output_filename> <torrent_filename> <index>`
  
- download: Downloads complete files
`./your_bittorrent download -o <output_filename> <torrent_filename>`



