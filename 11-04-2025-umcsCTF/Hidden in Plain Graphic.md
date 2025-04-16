# Hidden in Plain Graphic

Agent Ali, who are secretly a spy from Malaysia has been communicate with others spy from all around the world using secret technique . Intelligence agencies have been monitoring his activities, but so far, no clear evidence of his communications has surfaced. Can you find any suspicious traffic in this file?

## [plain_zight.pcap](https://umcsctfprelims.horizononsight.xyz/files/bc65940732fe5a26b0195e0c8c5cc9da/plain_zight.pcap?token=eyJ1c2VyX2lkIjozOSwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6OH0.Z_i3BA.8oh3A0skvLoFNhBaIS6PifNtLwA)

The first step I took in the Wireshark analysis was sorting the packets in ascending and descending order based on the Info column. This helped me quickly spot some interesting TCP packets:

![image](https://github.com/user-attachments/assets/084d02b8-2196-43dc-b190-7868d6f55887)


Upon closer inspection, I noticed that the stream begins with `.PNG` and ends with `IEND`, which strongly suggests that it's a PNG file. I then switched the data view to raw from hexdump and exported it as `image.bin`. 

After that, I simply renamed `image.bin` to `image.png`, and the image displayed successfully:

![image 1](https://github.com/user-attachments/assets/25104605-3e14-400b-b9b4-85eb223a0f07)


My instincts told me that this might involve image steganography, so I uploaded the file to [Aperi'Solve](https://www.aperisolve.com/) for analysis.

One of the tools used by Aperi'Solve is `zsteg`, which is designed to detect hidden data in PNG and BMP images particularly within the least significant bits (LSBs) of pixel values. From the `zsteg` analysis output, we were able to extract the flag.

![image 2](https://github.com/user-attachments/assets/8a2c0e44-990d-460f-bedb-7c9183d7971c)
