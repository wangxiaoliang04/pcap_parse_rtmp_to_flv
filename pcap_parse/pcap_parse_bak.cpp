// pcap_parse.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <fstream>
#include <vector>

uint32_t lastaudio = -1;
uint32_t lastVideo = -1;

uint32_t lastaudiolen = -1;
uint32_t lastVideolen = -1;

std::ofstream video_out_bin("out_binary.bin", std::ios::binary | std::ios::out);
int readPacket(std::ifstream & file, int chunk_size)
{
    uint32_t bodylen = -1;
    uint32_t bodysize = -1;
    bool  firstPacket = true;
    int calc_chunk_size = 0;
    do {
        std::vector<uint8_t> buffer1_1(1);
        if (file.read((char*)buffer1_1.data(), 1)) {
            // 成功读取数据，buffer中包含文件内容
            //std::cout << "文件大小: " << 1 << " 字节" << std::endl;
        }
        else {
            std::cerr << "读取文件失败1" << std::endl;
            return -1;
        }

        int32_t hdr = buffer1_1[0];
        uint8_t channel_id = buffer1_1[0] & 0x3F;
        hdr >>= 6; // header size indicator

        if (hdr == 0)
        {
            std::vector<uint8_t> buffer3(11);
            if (file.read((char*)buffer3.data(), 11)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << 12 << " 字节" << std::endl;
            }
            else {
                std::cerr << "读取文件失败2" << std::endl;
            }

            if (buffer3[6] == 0x08)
            {
                lastaudio = buffer1_1[0] & 0x3F;
            }

            if (buffer3[6] == 0x09)
            {
                lastVideo = buffer1_1[0] & 0x3F;
            }

            if(firstPacket) {
                uint32_t tmp0 = (uint32_t)buffer3[5];
                uint32_t tmp1 = ((uint32_t)buffer3[4]) << 8;
                uint32_t tmp2 = (((uint32_t)buffer3[3]) << 8) << 8;
                bodysize = tmp2 + tmp1 + tmp0;
                std::cout << "0 bodysize: " << bodysize << ", buffer3[6]:" << (uint32_t)(buffer3[6]) << std::endl;
                bodylen = bodysize;

                if (buffer3[6] == 0x08)
                {
                    lastaudiolen = bodysize;
                }
                if (buffer3[6] == 0x09)
                {
                    lastVideolen = bodysize;
                }

                std::cout << "0 lastaudiolen: " << lastaudiolen << ", lastVideolen:" << lastVideolen << std::endl;
            }

            uint32_t type = (int32_t)buffer3[6];
            if (!firstPacket)
            {
                //bodylen -= 12;
            }
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;
                if (buffer3[6] == 0x09 && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 && buffer4[4] == 0x00)
                {
                    int32_t bodysubLenTmp = bodysubLen;
                    bodysubLenTmp -= 5;
                    uint8_t* buffer4_1 = (uint8_t*)buffer4.data() + 5;
					do {
						char value = 0x00; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
						value = 0x00; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
						value = 0x00; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
						value = 0x01; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));

						uint32_t tmp0 = (uint32_t)buffer4_1[3];
						uint32_t tmp1 = ((uint32_t)buffer4_1[2]) << 8;
						uint32_t tmp2 = (((uint32_t)buffer4_1[1]) << 8) << 8;
						uint32_t tmp3 = (((uint32_t)buffer4_1[0]) << 8) << 8;
						int nalu_size = tmp3 + tmp2 + tmp1 + tmp0;

						video_out_bin.write((char*)buffer4_1 + 4, nalu_size);
						bodysubLenTmp -= 4;
						bodysubLenTmp -= nalu_size;
                        buffer4_1 += 4;
                        buffer4_1 += nalu_size;
					} while (bodysubLenTmp > 0);
                }
            }
            else {
                std::cerr << "读取文件失败3" << std::endl;
            }

            if (type == 1)
            {
                uint32_t tmp0 = (uint32_t)buffer4[3];
                uint32_t tmp1 = ((uint32_t)buffer4[2]) << 8;
                uint32_t tmp2 = (((uint32_t)buffer4[1]) << 8) << 8;
                uint32_t tmp3 = (((uint32_t)buffer4[0]) << 8) << 8;
                calc_chunk_size = tmp3 + tmp2 + tmp1 + tmp0;
            }

            bodylen -= bodysubLen;
            
            firstPacket = false;
        }
        else if (hdr == 1)
        {
            std::vector<uint8_t> buffer3(7);
            if (file.read((char*)buffer3.data(), 7)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << 7 << " 字节" << std::endl;
            }
            else {
                std::cerr << "读取文件失败4" << std::endl;
            }

            if (firstPacket) {
                uint32_t tmp0 = (uint32_t)buffer3[5];
                uint32_t tmp1 = ((uint32_t)buffer3[4]) << 8;
                uint32_t tmp2 = (((uint32_t)buffer3[3]) << 8) << 8;
				bodysize = tmp2 + tmp1 + tmp0;
                std::cout << "1 bodysize: " << bodysize << ",buffer3[6]:" << (uint32_t)(buffer3[6]) << std::endl;
                bodylen = bodysize;

                if (buffer3[6] == 0x08)
                {
                    lastaudiolen = bodysize;
                }
                if (buffer3[6] == 0x09)
                {
                    lastVideolen = bodysize;
                }
                std::cout << "1 lastaudiolen: " << lastaudiolen << ", lastVideolen:" << lastVideolen << std::endl;
            }

            uint32_t type = (int32_t)buffer3[6];   
            if (!firstPacket) {
                //bodylen -= 8;
            }

            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;

                if (buffer3[6] == 0x09 && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 && buffer4[4] == 0x00)
                {
                    int32_t bodysubLenTmp = bodysubLen;
                    bodysubLenTmp -= 5;
                    uint8_t* buffer4_1 = (uint8_t*)buffer4.data() + 5;
                    do {
                        char value = 0x00; // 写入的值
                        video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
                        value = 0x00; // 写入的值
                        video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
                        value = 0x00; // 写入的值
                        video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
                        value = 0x01; // 写入的值
                        video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));

                        uint32_t tmp0 = (uint32_t)buffer4_1[3];
                        uint32_t tmp1 = ((uint32_t)buffer4_1[2]) << 8;
                        uint32_t tmp2 = (((uint32_t)buffer4_1[1]) << 8) << 8;
                        uint32_t tmp3 = (((uint32_t)buffer4_1[0]) << 8) << 8;
                        int nalu_size = tmp3 + tmp2 + tmp1 + tmp0;

                        video_out_bin.write((char*)buffer4_1 + 4, nalu_size);
                        bodysubLenTmp -= 4;
                        bodysubLenTmp -= nalu_size;
                        buffer4_1 += 4;
                        buffer4_1 += nalu_size;
                    } while (bodysubLenTmp > 0);
                }
            }
            else {
                std::cerr << "读取文件失败5" << std::endl;
            }

            if (type == 1)
            {
                uint32_t tmp0 = (uint32_t)buffer4[3];
                uint32_t tmp1 = ((uint32_t)buffer4[2]) << 8;
                uint32_t tmp2 = (((uint32_t)buffer4[1]) << 8) << 8;
                uint32_t tmp3 = (((uint32_t)buffer4[0]) << 8) << 8;
                calc_chunk_size = tmp3 + tmp2 + tmp1 + tmp0;
            }

            bodylen -= bodysubLen;

            
            firstPacket = false;
        }
        else if (hdr == 2)
        {
            std::vector<uint8_t> buffer3(3);
            if (file.read((char*)buffer3.data(), 3)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << 3 << " 字节" << std::endl;
            }
            else {
                std::cerr << "读取文件失败6" << std::endl;
            }

            if (firstPacket) {
                //bodylen -= 4;
                if (lastaudio == (buffer1_1[0] & 0x3F))
                {
                    bodysize = lastaudiolen;
                    bodylen = lastaudiolen;
                }
                if (lastVideo == (buffer1_1[0] & 0x3F))
                {
                    bodysize = lastVideolen;
                    bodylen = lastVideolen;
                }
            }

            //int32_t tmp0 = (int32_t)buffer3[5];
            //int32_t tmp1 = ((int32_t)buffer3[4]) << 8;
            //int32_t tmp2 = (((int32_t)buffer3[3]) << 8) << 8;
            //bodysize = tmp2 + tmp1 + tmp0;

            //bodylen = bodysize;
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;

                if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 && buffer4[4] == 0x00)
                {
                    int32_t bodysubLenTmp = bodysubLen;
                    bodysubLenTmp -= 5;
                    uint8_t* buffer4_1 = (uint8_t*)buffer4.data() + 5;

					do {
						char value = 0x00; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
						value = 0x00; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
						value = 0x00; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
						value = 0x01; // 写入的值
						video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));

                        uint32_t tmp0 = (uint32_t)buffer4_1[3];
                        uint32_t tmp1 = ((uint32_t)buffer4_1[2]) << 8;
                        uint32_t tmp2 = (((uint32_t)buffer4_1[1]) << 8) << 8;
                        uint32_t tmp3 = (((uint32_t)buffer4_1[0]) << 8) << 8;
                        int nalu_size = tmp3 + tmp2 + tmp1 + tmp0;

						video_out_bin.write((char*)buffer4_1 + 4, nalu_size);
                        bodysubLenTmp -= 4;
                        bodysubLenTmp -= nalu_size;
                        buffer4_1 += 4;
                        buffer4_1 += nalu_size;

					} while (bodysubLenTmp > 0);
                }
            }
            else {
                std::cerr << "读取文件失败7" << std::endl;
            }

            bodylen -= bodysubLen;

            firstPacket = false;
        }
        else if (hdr == 3)
        {
            //std::vector<uint8_t> buffer3(3);
            //if (file.read((char*)buffer3.data(), 3)) {
            //    // 成功读取数据，buffer中包含文件内容
            //    std::cout << "文件大小: " << 3 << " 字节" << std::endl;
            //}
            //else {
            //    std::cerr << "读取文件失败" << std::endl;
            //}

            //int32_t tmp0 = (int32_t)buffer3[5];
            //int32_t tmp1 = ((int32_t)buffer3[4]) << 8;
            //int32_t tmp2 = (((int32_t)buffer3[3]) << 8) << 8;
            //bodysize = tmp2 + tmp1 + tmp0;

            if (firstPacket) {
                //bodylen += 1;
                if (lastaudio == (buffer1_1[0] & 0x3F))
                {
                    bodysize = lastaudiolen;
                    bodylen = lastaudiolen;
                }
                if (lastVideo == (buffer1_1[0] & 0x3F))
                {
                    bodysize = lastVideolen;
                    bodylen = lastVideolen;
                }
            }

            //bodylen = bodysize;
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;

                if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 && buffer4[4] == 0x00)
                {
                    int32_t bodysubLenTmp = bodysubLen;
                    bodysubLenTmp -= 5;
                    uint8_t* buffer4_1 = (uint8_t*)buffer4.data() + 5;

                    do {
                    char value = 0x00; // 写入的值
                    video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
                    value = 0x00; // 写入的值
                    video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
                    value = 0x00; // 写入的值
                    video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
                    value = 0x01; // 写入的值
                    video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));

                    uint32_t tmp0 = (uint32_t)buffer4_1[3];
                    uint32_t tmp1 = ((uint32_t)buffer4_1[2]) << 8;
                    uint32_t tmp2 = (((uint32_t)buffer4_1[1]) << 8) << 8;
                    uint32_t tmp3 = (((uint32_t)buffer4_1[0]) << 8) << 8;
                    int nalu_size = tmp3 + tmp2 + tmp1 + tmp0;
                    video_out_bin.write((char*)buffer4_1 + 4, nalu_size);

                    bodysubLenTmp -= 4;
                    bodysubLenTmp -= nalu_size;
                    buffer4_1 += 4;
                    buffer4_1 += nalu_size;
                    } while (bodysubLenTmp > 0);
                }
            }
            else {
                std::cerr << "读取文件失败8" << std::endl;
            }

            bodylen -= bodysubLen;

            firstPacket = false;
        }
    } while (bodylen > 0);
    return calc_chunk_size;
}

int main() {
    std::ifstream file("E:\\BaiduNetdiskDownload\\ffmpeg_vs2019\\msvc\\bin\\x64\\1639_2", std::ios::binary);
    if (!file) {
        std::cerr << "无法打开文件" << std::endl;
        return 1;
    }

    // 确定文件大小
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // 分配内存，并读取数据
    std::vector<uint8_t> buffer(1537);
    if (file.read((char*)buffer.data(), 1537)) {
        // 成功读取数据，buffer中包含文件内容
        std::cout << "文件大小: " << 1537 << " 字节" << std::endl;
    }
    else {
        std::cerr << "读取文件失败" << std::endl;
    }

    std::vector<uint8_t> buffer1(3073);
    if (file.read((char*)buffer1.data(), 3073)) {
        // 成功读取数据，buffer中包含文件内容
        std::cout << "文件大小: " << 3073 << " 字节" << std::endl;
    }
    else {
        std::cerr << "读取文件失败" << std::endl;
    }

    std::vector<uint8_t> buffer2(1536);
    if (file.read((char*)buffer2.data(), 1536)) {
        // 成功读取数据，buffer中包含文件内容
        std::cout << "文件大小: " << 1536 << " 字节" << std::endl;
    }
    else {
        std::cerr << "读取文件失败" << std::endl;
    }

    //connect
    readPacket(file, 128);
    //Set Chunk Size
    int chunk_size = readPacket(file, 128);
    //Window Acknowledgement Size
    readPacket(file, chunk_size);
    //Set Peer Bandwidth
    readPacket(file, chunk_size);
    //_result
    readPacket(file, chunk_size);
    //onBWDone
    readPacket(file, chunk_size);
    //Set Chunk Size
    readPacket(file, chunk_size);
    //releaseStream
    readPacket(file, chunk_size);
    //FCPublish
    readPacket(file, chunk_size);
    //createStream
    readPacket(file, chunk_size);
    //_result
    readPacket(file, chunk_size);

    //_checkbw
    readPacket(file, chunk_size);

    //publish
    readPacket(file, chunk_size);

    //onStatus
    readPacket(file, chunk_size);

    //setDataFrame
    readPacket(file, chunk_size);

    //video Data
    readPacket(file, chunk_size);

    //audio Data
    readPacket(file, chunk_size);

    while (!file.eof()) {
        readPacket(file, chunk_size);
    }

    file.close();
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
