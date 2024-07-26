// pcap_parse.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <ws2tcpip.h>

//在publish或者play之后就是开始传输媒体数据了，媒体数据分为3种，script脚本数据、video视频数据、audio音频数据。
// 首先需要传输的是脚本数据onMetaData，也称为元数据。onMetaData主要描述音视频的编码格式的相关参数。
//
//如果是发布端向服务器推流，则onMetaData的方向是C->S，如果是播放器向服务器拉流，则onMetaData的方向是S->C。
//
//videocodecid = 7对应的视频编码是H.264
//audiocodecid = 7对应的音频编码是G711A
//audiocodecid = 8对应的音频编码是G711U
//audiocodecid = 10对应的音频编码是AAC
//————————————————
//
//版权声明：本文为博主原创文章，遵循 CC 4.0 BY - SA 版权协议，转载请附上原文出处链接和本声明。
//
//原文链接：https ://blog.csdn.net/Jacob_job/article/details/81866239

uint32_t lastaudio = -1;
uint32_t lastVideo = -1;

uint32_t lastaudiolen = -1;
uint32_t lastVideolen = -1;
uint32_t index_video = 0;
uint32_t index_video_packet_size = 0;

uint8_t profile = 0;
int sampleRate = 0;
uint8_t channel = 0;

int videocodecid_ = -1;
int audiocodecid_ = -1;

#define ADTS_HEADER_LEN  7;

const int sampling_frequencies[] = {
    96000,  // 0x0
    88200,  // 0x1
    64000,  // 0x2
    48000,  // 0x3
    44100,  // 0x4
    32000,  // 0x5
    24000,  // 0x6
    22050,  // 0x7
    16000,  // 0x8
    12000,  // 0x9
    11025,  // 0xa
    8000   // 0xb
    // 0xc d e f是保留的
};

int adts_header(char* const p_adts_header, const int data_length,
    const int profile, const int samplerate,
    const int channels)
{

    int sampling_frequency_index = 3; // 默认使用48000hz
    int adtsLen = data_length + 7;
    //ADTS不是单纯的data，是hearder+data的，所以加7这个头部hearder的长度，这里7是因为后面protection absent位设为1，不做校验，所以直接加7，如果做校验，可能会是9

    int frequencies_size = sizeof(sampling_frequencies) / sizeof(sampling_frequencies[0]);
    int i = 0;
    for (i = 0; i < frequencies_size; i++)   //查找采样率
    {
        if (sampling_frequencies[i] == samplerate)
        {
            sampling_frequency_index = i;
            break;
        }
    }
    if (i >= frequencies_size)
    {
        printf("unsupport samplerate:%d\n", samplerate);
        return -1;
    }

    p_adts_header[0] = 0xff;         //syncword:0xfff                          高8bits
    p_adts_header[1] = 0xf0;         //syncword:0xfff                          低4bits
    p_adts_header[1] |= (0 << 3);    //MPEG Version:0 for MPEG-4,1 for MPEG-2  1bit
    p_adts_header[1] |= (0 << 1);    //Layer:0                                 2bits
    p_adts_header[1] |= 1;           //protection absent:1                     1bit

    p_adts_header[2] = (profile) << 6;            //profile:profile               2bits
    p_adts_header[2] |= (sampling_frequency_index & 0x0f) << 2; //sampling frequency index:sampling_frequency_index  4bits
    p_adts_header[2] |= (0 << 1);             //private bit:0                   1bit
    p_adts_header[2] |= (channels & 0x04) >> 2; //channel configuration:channels  高1bit

    p_adts_header[3] = (channels & 0x03) << 6; //channel configuration:channels 低2bits
    p_adts_header[3] |= (0 << 5);               //original：0                1bit
    p_adts_header[3] |= (0 << 4);               //home：0                    1bit
    p_adts_header[3] |= (0 << 3);               //copyright id bit：0        1bit
    p_adts_header[3] |= (0 << 2);               //copyright id start：0      1bit
    p_adts_header[3] |= ((adtsLen & 0x1800) >> 11);           //frame length：value   高2bits

    p_adts_header[4] = (uint8_t)((adtsLen & 0x7f8) >> 3);     //frame length:value    中间8bits
    p_adts_header[5] = (uint8_t)((adtsLen & 0x7) << 5);       //frame length:value    低3bits
    p_adts_header[5] |= 0x1f;                                 //buffer fullness:0x7ff 高5bits
    p_adts_header[6] = 0xfc;      //11111100       //buffer fullness:0x7ff 低6bits
    // number_of_raw_data_blocks_in_frame：
    //    表示ADTS帧中有number_of_raw_data_blocks_in_frame + 1个AAC原始帧。

    return 0;
}

union av_intfloat64 {
    uint64_t i;
    double   f;
};

/**
 * Reinterpret a 64-bit integer as a double.
 */
static double av_int2double(uint64_t i)
{
    union av_intfloat64 v;
    v.i = i;
    return v.f;
}

int readPacket(std::ifstream & file, int chunk_size, FILE* file_video_out, FILE* file_audio_out)
{
    uint32_t bodylen = -1;
    uint32_t bodysize = -1;
    bool  firstPacket = true;
    int calc_chunk_size = 0;
    std::vector<uint8_t> vecMerged;
    std::vector<uint8_t> vecMergedAudio;
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
                if (firstPacket == true)
                {
                    if (buffer3[6] == 0x09 && ((buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/) /*|| (buffer4[1] == 0x00 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*//*)*/ ))
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (buffer3[6] == 0x09 && ((buffer4[1] == 0x00 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)))
                    {
                        int nal_len_size = (buffer4[26]&3) + 1;
                        int num_arrays = buffer4[27];
                        int nal_len = 0;
                        for (int i = 0; i < num_arrays; i++)
                        {
                            int type = buffer4[28 + nal_len] & 0x3f;
                            int cnt = (buffer4[29 + nal_len] << 8) + buffer4[30 + nal_len];
                            for (int j = 0; j < cnt; j++)
                            {
                                int nal_size = (buffer4[31 + nal_len] << 8) + buffer4[32 + nal_len];

                                uint8_t tmp1 = ((((/*5 +*/ nal_size) >> 8) >> 8) >> 8) & 0xff;
                                uint8_t tmp2 = (((/*5 +*/ nal_size) >> 8) >> 8) & 0xff;
                                uint8_t tmp3 = ((/*5 +*/ nal_size) >> 8) & 0xff;
                                uint8_t tmp4 = (/*5 +*/ nal_size) & 0xff;
                                vecMerged.push_back(tmp1);
                                vecMerged.push_back(tmp2);
                                vecMerged.push_back(tmp3);
                                vecMerged.push_back(tmp4);
                                vecMerged.insert(vecMerged.end(), buffer4.begin() + nal_len  +33, buffer4.begin() + nal_len + 33 + nal_size);
                                nal_len += (5 + nal_size);
                            }
                        }
                    }
                    else if (buffer3[6] == 0x08 && buffer4[1] == 0x00)
                    {
                        profile = (buffer4[2] & 0xF8) >> 4;
                        uint8_t sampleRate_index = ((buffer4[2] & 0x07) << 1) + ((buffer4[3] & 0x80) >> 7);
                        sampleRate = sampling_frequencies[sampleRate_index];
                        channel = (buffer4[3] & 0x78) >> 3;
                    }
                    else if (buffer3[6] == 0x08/* && buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (buffer3[6] == 0x08 && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                    else if (buffer3[6] == 0x12)
                    {
                        uint8_t type = buffer4[0]; //0x02 string
                        uint32_t tmp1 = buffer4[1];
                        uint32_t tmp2 = buffer4[2];
                        uint32_t body_len = tmp2 + (tmp1 << 8);
                        
                        type = buffer4[3 + body_len];
                        uint32_t tmp3 = buffer4[3 + body_len + 1];
                        uint32_t tmp4 = buffer4[3 + body_len + 2];
                        uint32_t body_len1 = tmp4 + (tmp3 << 8);
                        std::cout << " body_len:" << body_len << std::endl;

                        type = buffer4[3 + body_len + 2 + 1 + body_len1];
                        std::cout << " array type:" << type << std::endl;

                        uint32_t tmpArr1 = buffer4[3 + body_len + 2 + 1 + body_len1 + 1];
                        uint32_t tmpArr2 = buffer4[3 + body_len + 2 + 1 + body_len1 + 2];
                        uint32_t tmpArr3 = buffer4[3 + body_len + 2 + 1 + body_len1 + 3];
                        uint32_t tmpArr4 = buffer4[3 + body_len + 2 + 1 + body_len1 + 4];

                        uint32_t arr_index = 3 + body_len + 2 + 1 + body_len1 + 4 + 1;
                        uint8_t arr_len = (((tmpArr1 << 8) << 8) << 8) + ((tmpArr2 << 8) << 8) + ((tmpArr3) << 8) + tmpArr4;
                        for (int index = 0; index < arr_len; index++)
                        {
                            uint32_t tmpArrLen1 = buffer4[arr_index];
                            uint32_t tmpArrLen2 = buffer4[arr_index + 1];

                            uint32_t name_len = (tmpArrLen1 << 8) + tmpArrLen2;

                            char szTmp[1024] = { 0 };
                            memcpy(szTmp, &buffer4[arr_index + 1 + 1], name_len);

                            uint8_t type = buffer4[arr_index + 1 + name_len + 1];
                            std::cout << " array type:" << type << std::endl;
                            if (type == 0)
                            {
                                uint64_t host_value = 0;
                                memcpy(&host_value, &buffer4[arr_index + 1 + name_len + 1 + 1], 8);
                                //actual_len += sizeof(uint64_t);
                                host_value = ntohll(host_value);
                                double dhost = av_int2double(host_value);
                                arr_index = arr_index + 1 + name_len + 1 + 1 + 8;
                                if (0 == strcmp(szTmp, "videocodecid"))
                                {
                                    videocodecid_ = dhost;
                                }
                                if (0 == strcmp(szTmp, "audiocodecid"))
                                {
                                    audiocodecid_ = dhost;
                                }
                            }
                            else if (type == 1)
                            {
                                uint8_t host_value = 0;
                                host_value = buffer4[arr_index + 1 + name_len + 1 + 1];
                                arr_index = arr_index + 1 + name_len + 1 + 1 + 1;
                            }
                            else if (type == 2)
                            {
                                uint16_t host_value = 0;
                                /*if (fread(&host_value, sizeof(uint16_t), 1, fp) != 1)
                                {
                                    printf("can not read ip_header, i:%d\n", i);
                                    break;
                                }*/

                                uint8_t str_len1 = buffer4[arr_index + 1 + name_len + 1 + 1];
                                uint8_t str_len2 = buffer4[arr_index + 1 + name_len + 1 + 2];
                                host_value = (str_len1 << 8) + str_len2;
                                arr_index = arr_index + 1 + name_len + 1 + 2 + host_value + 1;
                            }
                        }
                        arr_index += 3;
                    }
                }
                else
                {
                    if (buffer3[6] == 0x09)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                    }
                    else if (buffer3[6] == 0x08 /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (buffer3[6] == 0x08 && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
						char adts_header_buf[7] = { 0 };
						adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
						//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

						std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
						vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());
                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
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
                if (firstPacket == true)
                {
                    if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());
                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
						char adts_header_buf[7] = { 0 };
						adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
						//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

						std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
						vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
                else
                {
                        if (lastVideo == channel_id)
                        {
                            vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                        }
                        else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                        {
                            //char adts_header_buf[7] = { 0 };
                            //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                            ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                            //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                            //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                            vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                        }
                        else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                        {
							char adts_header_buf[7] = { 0 };
							adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
							//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

							std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
							vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                            vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                        }
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

            //bodylen = bodysize;
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;

                if (firstPacket == true)
                {
                    if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
						char adts_header_buf[7] = { 0 };
						adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
						//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

						std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
						vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
                else
                {
                        if (lastVideo == channel_id)
                        {
                            vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                        }
                        else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                        {
                            //char adts_header_buf[7] = { 0 };
                            //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                            ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                            //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                            //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                            vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                        }
                        else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                        {
							char adts_header_buf[7] = { 0 };
							adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
							//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

							std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
							vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                            vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                        }
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

            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;
                if (firstPacket == true)
                {
                    if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
						char adts_header_buf[7] = { 0 };
						adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
						//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

						std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
						vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
                else
                {
                    if (lastVideo == channel_id)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
						char adts_header_buf[7] = { 0 };
						adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
						//vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

						std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
						vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
            }
            else {
                std::cerr << "读取文件失败8" << std::endl;
            }

            bodylen -= bodysubLen;

            firstPacket = false;
        }
    } while (bodylen > 0);

    if (vecMerged.size() > 0)
    {
        //std::ofstream video_out_bin("E:\\BaiduNetdiskDownload\\ffmpeg_vs2019\\msvc\\bin\\x64\\out_binary.bin", std::ios::binary | std::ios::app);
        int32_t bodysubLenTmp = vecMerged.size();
        //bodysubLenTmp -= 5;
        //uint8_t* buffer4_1 = (uint8_t*)vecMerged.data();
        do {
            char value = 0x00; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);
            value = 0x00; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);
            value = 0x00; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);
            value = 0x01; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);

            uint32_t tmp0 = (uint32_t)vecMerged[3];
            uint32_t tmp1 = ((uint32_t)vecMerged[2]) << 8;
            uint32_t tmp2 = (((uint32_t)vecMerged[1]) << 8) << 8;
            uint32_t tmp3 = (((uint32_t)vecMerged[0]) << 8) << 8;
            int nalu_size = tmp3 + tmp2 + tmp1 + tmp0;
            int nalu_size_tmp = nalu_size;
            size_t written_bytes = 0;
            size_t written = 0;
            do {
                vecMerged.erase(vecMerged.begin(), std::next(vecMerged.begin(), 4));
                written = fwrite(vecMerged.data() + written_bytes, 1, nalu_size_tmp, file_video_out);
                if (written != nalu_size_tmp) {
                    std::cout << "Error writing to file nalu_size:" << nalu_size_tmp << ", written:" << written << std::endl;
                }
                if (0 == written)
                {
                    return -1;
                }
                nalu_size_tmp -= written;
                written_bytes += written;
            } while (nalu_size_tmp != 0);

            //video_out_bin.write((char*)(buffer4_1 + 4), nalu_size);
            //video_out_bin.flush();
            index_video_packet_size += 4;
            index_video_packet_size += nalu_size;

            bodysubLenTmp -= 4;
            bodysubLenTmp -= nalu_size;
            //buffer4_1 += 4;
            //buffer4_1 += nalu_size;
            vecMerged.erase(vecMerged.begin(), std::next(vecMerged.begin(), nalu_size));
        } while (bodysubLenTmp > 0);
        index_video++;
        //video_out_bin.close();
        std::cout << "0 video packet count: " << index_video << ", index_video_packet_size:" << index_video_packet_size << std::endl;
    }

    if (vecMergedAudio.size() > 0)
    {
        int nalu_size_tmp = vecMergedAudio.size();
        size_t written_bytes = 0;
        size_t written = 0;
        do {
            //vecMerged.erase(vecMerged.begin(), std::next(vecMerged.begin(), 4));
            written = fwrite(vecMergedAudio.data() + written_bytes, 1, nalu_size_tmp, file_audio_out);
            if (written != nalu_size_tmp) {
                std::cout << "Error writing to file nalu_size:" << nalu_size_tmp << ", written:" << written << std::endl;
            }
            if (0 == written)
            {
                return -1;
            }
            nalu_size_tmp -= written;
            written_bytes += written;
        } while (nalu_size_tmp != 0);
    }

    return calc_chunk_size;
}

uint8_t sHeader[] = { 0x46, 0x4c, 0x56, 0x01, 0x05, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00 };
int readPacket_Flv(std::ifstream& file, int chunk_size, FILE* file_video_out, FILE* file_audio_out)
{
    int tagType = 0;
    int lastType = 0;
    uint32_t ts = 0;
    uint32_t last_ts = 0;
    uint32_t bodylen = -1;
    uint32_t bodysize = -1;
    bool  firstPacket = true;
    int calc_chunk_size = 0;
    std::vector<uint8_t> vecMerged;
    std::vector<uint8_t> vecMergedAudio;
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

            if (firstPacket) {
                uint32_t ts0 = (uint32_t)buffer3[2];
                uint32_t ts1 = ((uint32_t)buffer3[1]) << 8;
                uint32_t ts2 = (((uint32_t)buffer3[0]) << 8) << 8;
                ts = ts0 + ts1 + ts2;

                if (ts == 0xffffff) {
                    //扩展时间戳后面加上把
                    std::vector<uint8_t> buffertsExt(4);
                    if (file.read((char*)buffertsExt.data(), 4)) {
                        // 成功读取数据，buffer中包含文件内容
                        uint32_t ts0 = (uint32_t)buffertsExt[3];
                        uint32_t ts1 = ((uint32_t)buffertsExt[2]) << 8;
                        uint32_t ts2 = (((uint32_t)buffertsExt[1]) << 8) << 8;
                        uint32_t ts3 = ((((uint32_t)buffertsExt[0]) << 8) << 8) << 8;
                        ts = ts0 + ts1 + ts2 + ts3;
                    }
                    else {
                        std::cerr << "读取文件失败2" << std::endl;
                    }
                }

                last_ts = ts;

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
            tagType = type;
            lastType = type;
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;
                if (firstPacket == true)
                {
                    if (buffer3[6] == 0x09 && ((buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/) /*|| (buffer4[1] == 0x00 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*//*)*/))
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (buffer3[6] == 0x09 && ((buffer4[1] == 0x00 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)))
                    {
                        int nal_len_size = (buffer4[26] & 3) + 1;
                        int num_arrays = buffer4[27];
                        int nal_len = 0;
                        for (int i = 0; i < num_arrays; i++)
                        {
                            int type = buffer4[28 + nal_len] & 0x3f;
                            int cnt = (buffer4[29 + nal_len] << 8) + buffer4[30 + nal_len];
                            for (int j = 0; j < cnt; j++)
                            {
                                int nal_size = (buffer4[31 + nal_len] << 8) + buffer4[32 + nal_len];

                                uint8_t tmp1 = ((((/*5 +*/ nal_size) >> 8) >> 8) >> 8) & 0xff;
                                uint8_t tmp2 = (((/*5 +*/ nal_size) >> 8) >> 8) & 0xff;
                                uint8_t tmp3 = ((/*5 +*/ nal_size) >> 8) & 0xff;
                                uint8_t tmp4 = (/*5 +*/ nal_size) & 0xff;
                                vecMerged.push_back(tmp1);
                                vecMerged.push_back(tmp2);
                                vecMerged.push_back(tmp3);
                                vecMerged.push_back(tmp4);
                                vecMerged.insert(vecMerged.end(), buffer4.begin() + nal_len + 33, buffer4.begin() + nal_len + 33 + nal_size);
                                nal_len += (5 + nal_size);
                            }
                        }
                    }
                    else if (buffer3[6] == 0x08 && buffer4[1] == 0x00)
                    {
                        profile = (buffer4[2] & 0xF8) >> 4;
                        uint8_t sampleRate_index = ((buffer4[2] & 0x07) << 1) + ((buffer4[3] & 0x80) >> 7);
                        sampleRate = sampling_frequencies[sampleRate_index];
                        channel = (buffer4[3] & 0x78) >> 3;
                    }
                    else if (buffer3[6] == 0x08/* && buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (buffer3[6] == 0x08 && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                    else if (buffer3[6] == 0x12)
                    {
                        uint8_t type = buffer4[0]; //0x02 string
                        uint32_t tmp1 = buffer4[1];
                        uint32_t tmp2 = buffer4[2];
                        uint32_t body_len = tmp2 + (tmp1 << 8);

                        type = buffer4[3 + body_len];
                        uint32_t tmp3 = buffer4[3 + body_len + 1];
                        uint32_t tmp4 = buffer4[3 + body_len + 2];
                        uint32_t body_len1 = tmp4 + (tmp3 << 8);
                        std::cout << " body_len:" << body_len << std::endl;

                        type = buffer4[3 + body_len + 2 + 1 + body_len1];
                        std::cout << " array type:" << type << std::endl;

                        uint32_t tmpArr1 = buffer4[3 + body_len + 2 + 1 + body_len1 + 1];
                        uint32_t tmpArr2 = buffer4[3 + body_len + 2 + 1 + body_len1 + 2];
                        uint32_t tmpArr3 = buffer4[3 + body_len + 2 + 1 + body_len1 + 3];
                        uint32_t tmpArr4 = buffer4[3 + body_len + 2 + 1 + body_len1 + 4];

                        uint32_t arr_index = 3 + body_len + 2 + 1 + body_len1 + 4 + 1;
                        uint8_t arr_len = (((tmpArr1 << 8) << 8) << 8) + ((tmpArr2 << 8) << 8) + ((tmpArr3) << 8) + tmpArr4;
                        for (int index = 0; index < arr_len; index++)
                        {
                            uint32_t tmpArrLen1 = buffer4[arr_index];
                            uint32_t tmpArrLen2 = buffer4[arr_index + 1];

                            uint32_t name_len = (tmpArrLen1 << 8) + tmpArrLen2;

                            char szTmp[1024] = { 0 };
                            memcpy(szTmp, &buffer4[arr_index + 1 + 1], name_len);

                            uint8_t type = buffer4[arr_index + 1 + name_len + 1];
                            std::cout << " array type:" << type << std::endl;
                            if (type == 0)
                            {
                                uint64_t host_value = 0;
                                memcpy(&host_value, &buffer4[arr_index + 1 + name_len + 1 + 1], 8);
                                //actual_len += sizeof(uint64_t);
                                host_value = ntohll(host_value);
                                double dhost = av_int2double(host_value);
                                arr_index = arr_index + 1 + name_len + 1 + 1 + 8;
                                if (0 == strcmp(szTmp, "videocodecid"))
                                {
                                    videocodecid_ = dhost;
                                }
                                if (0 == strcmp(szTmp, "audiocodecid"))
                                {
                                    audiocodecid_ = dhost;
                                }
                            }
                            else if (type == 1)
                            {
                                uint8_t host_value = 0;
                                host_value = buffer4[arr_index + 1 + name_len + 1 + 1];
                                arr_index = arr_index + 1 + name_len + 1 + 1 + 1;
                            }
                            else if (type == 2)
                            {
                                uint16_t host_value = 0;
                                /*if (fread(&host_value, sizeof(uint16_t), 1, fp) != 1)
                                {
                                    printf("can not read ip_header, i:%d\n", i);
                                    break;
                                }*/

                                uint8_t str_len1 = buffer4[arr_index + 1 + name_len + 1 + 1];
                                uint8_t str_len2 = buffer4[arr_index + 1 + name_len + 1 + 2];
                                host_value = (str_len1 << 8) + str_len2;
                                arr_index = arr_index + 1 + name_len + 1 + 2 + host_value + 1;
                            }
                        }
                        arr_index += 3;
                    }
                }
                else
                {
                    if (buffer3[6] == 0x09)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                    }
                    else if (buffer3[6] == 0x08 /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (buffer3[6] == 0x08 && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());
                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
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
                uint32_t ts0 = (uint32_t)buffer3[2];
                uint32_t ts1 = ((uint32_t)buffer3[1]) << 8;
                uint32_t ts2 = (((uint32_t)buffer3[0]) << 8) << 8;
                ts = ts0 + ts1 + ts2;

                if (ts == 0xffffff) {
                    //扩展时间戳后面加上把
                    std::vector<uint8_t> buffertsExt(4);
                    if (file.read((char*)buffertsExt.data(), 4)) {
                        // 成功读取数据，buffer中包含文件内容
                        uint32_t ts0 = (uint32_t)buffertsExt[3];
                        uint32_t ts1 = ((uint32_t)buffertsExt[2]) << 8;
                        uint32_t ts2 = (((uint32_t)buffertsExt[1]) << 8) << 8;
                        uint32_t ts3 = ((((uint32_t)buffertsExt[0]) << 8) << 8) << 8;
                        ts = ts0 + ts1 + ts2 + ts3;
                    }
                    else {
                        std::cerr << "读取文件失败2" << std::endl;
                    }
                }

                last_ts = ts;

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
            tagType = type;
            lastType = type;
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;
                if (firstPacket == true)
                {
                    if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());
                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
                else
                {
                    if (lastVideo == channel_id)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
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
                uint32_t ts0 = (uint32_t)buffer3[2];
                uint32_t ts1 = ((uint32_t)buffer3[1]) << 8;
                uint32_t ts2 = (((uint32_t)buffer3[0]) << 8) << 8;
                ts = ts0 + ts1 + ts2;

                if (ts == 0xffffff) {
                    //扩展时间戳后面加上把
                    std::vector<uint8_t> buffertsExt(4);
                    if (file.read((char*)buffertsExt.data(), 4)) {
                        // 成功读取数据，buffer中包含文件内容
                        uint32_t ts0 = (uint32_t)buffertsExt[3];
                        uint32_t ts1 = ((uint32_t)buffertsExt[2]) << 8;
                        uint32_t ts2 = (((uint32_t)buffertsExt[1]) << 8) << 8;
                        uint32_t ts3 = ((((uint32_t)buffertsExt[0]) << 8) << 8) << 8;
                        ts = ts0 + ts1 + ts2 + ts3;
                    }
                    else {
                        std::cerr << "读取文件失败2" << std::endl;
                    }
                }

                last_ts = ts;

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

                //ts = last_ts;
                tagType = lastType;
            }
            
            //bodylen = bodysize;
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;

                if (firstPacket == true)
                {
                    if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
                else
                {
                    if (lastVideo == channel_id)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
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

            if (firstPacket) {
                ts = last_ts;
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
                tagType = lastType;
            }
            
            int32_t bodysubLen = bodylen > chunk_size ? chunk_size : bodylen;
            std::vector<uint8_t> buffer4(bodysubLen);
            if (file.read((char*)buffer4.data(), bodysubLen)) {
                // 成功读取数据，buffer中包含文件内容
                //std::cout << "文件大小: " << bodysubLen << " 字节" << std::endl;
                if (firstPacket == true)
                {
                    if (lastVideo == channel_id && buffer4[1] == 0x01 && buffer4[2] == 0x00 && buffer4[3] == 0x00 /*&& buffer4[4] == 0x00*/)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin() + 5, buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
                else
                {
                    if (lastVideo == channel_id)
                    {
                        vecMerged.insert(vecMerged.end(), buffer4.begin(), buffer4.end());
                    }
                    else if (lastaudio == channel_id /*&& buffer4[1] == 0x01*/ && (audiocodecid_ == 7 || audiocodecid_ == 8))
                    {
                        //char adts_header_buf[7] = { 0 };
                        //adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        ////vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        //std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        //vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 1 /*+ 2*/, buffer4.end());
                    }
                    else if (lastaudio == channel_id && buffer4[1] == 0x01 && audiocodecid_ == 10)
                    {
                        char adts_header_buf[7] = { 0 };
                        adts_header(adts_header_buf, buffer4.size() - 2, profile, sampleRate, channel);
                        //vecMergedAudio.insert((uint8_t)(adts_header_buf[0]));

                        std::vector<uint8_t> vec(std::begin(adts_header_buf), std::end(adts_header_buf));
                        vecMergedAudio.insert(vecMergedAudio.end(), vec.begin(), vec.end());

                        vecMergedAudio.insert(vecMergedAudio.end(), buffer4.begin() + 2, buffer4.end());
                    }
                }
            }
            else {
                std::cerr << "读取文件失败8" << std::endl;
            }

            bodylen -= bodysubLen;

            firstPacket = false;
        }
    } while (bodylen > 0);

    if (vecMerged.size() > 0)
    {
        //std::ofstream video_out_bin("E:\\BaiduNetdiskDownload\\ffmpeg_vs2019\\msvc\\bin\\x64\\out_binary.bin", std::ios::binary | std::ios::app);
        int32_t bodysubLenTmp = vecMerged.size();
        //bodysubLenTmp -= 5;
        //uint8_t* buffer4_1 = (uint8_t*)vecMerged.data();
        do {
            char value = 0x00; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);
            value = 0x00; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);
            value = 0x00; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);
            value = 0x01; // 写入的值
            //video_out_bin.write(reinterpret_cast<const char*>(&value), sizeof(value));
            fwrite(&value, sizeof(char), 1, file_video_out);

            uint32_t tmp0 = (uint32_t)vecMerged[3];
            uint32_t tmp1 = ((uint32_t)vecMerged[2]) << 8;
            uint32_t tmp2 = (((uint32_t)vecMerged[1]) << 8) << 8;
            uint32_t tmp3 = (((uint32_t)vecMerged[0]) << 8) << 8;
            int nalu_size = tmp3 + tmp2 + tmp1 + tmp0;
            int nalu_size_tmp = nalu_size;
            size_t written_bytes = 0;
            size_t written = 0;
            do {
                vecMerged.erase(vecMerged.begin(), std::next(vecMerged.begin(), 4));
                written = fwrite(vecMerged.data() + written_bytes, 1, nalu_size_tmp, file_video_out);
                if (written != nalu_size_tmp) {
                    std::cout << "Error writing to file nalu_size:" << nalu_size_tmp << ", written:" << written << std::endl;
                }
                if (0 == written)
                {
                    return -1;
                }
                nalu_size_tmp -= written;
                written_bytes += written;
            } while (nalu_size_tmp != 0);

            //video_out_bin.write((char*)(buffer4_1 + 4), nalu_size);
            //video_out_bin.flush();
            index_video_packet_size += 4;
            index_video_packet_size += nalu_size;

            bodysubLenTmp -= 4;
            bodysubLenTmp -= nalu_size;
            //buffer4_1 += 4;
            //buffer4_1 += nalu_size;
            vecMerged.erase(vecMerged.begin(), std::next(vecMerged.begin(), nalu_size));
        } while (bodysubLenTmp > 0);
        index_video++;
        //video_out_bin.close();
        std::cout << "0 video packet count: " << index_video << ", index_video_packet_size:" << index_video_packet_size << std::endl;
    }

    if (vecMergedAudio.size() > 0)
    {
        int nalu_size_tmp = vecMergedAudio.size();
        size_t written_bytes = 0;
        size_t written = 0;
        do {
            //vecMerged.erase(vecMerged.begin(), std::next(vecMerged.begin(), 4));
            written = fwrite(vecMergedAudio.data() + written_bytes, 1, nalu_size_tmp, file_audio_out);
            if (written != nalu_size_tmp) {
                std::cout << "Error writing to file nalu_size:" << nalu_size_tmp << ", written:" << written << std::endl;
            }
            if (0 == written)
            {
                return -1;
            }
            nalu_size_tmp -= written;
            written_bytes += written;
        } while (nalu_size_tmp != 0);
    }

    return calc_chunk_size;
}

int main() {
    std::ifstream file("E:\\BaiduNetdiskDownload\\ffmpeg_vs2019\\msvc\\bin\\x64\\rtmp_hevc_2", std::ios::binary);
    if (!file) {
        std::cerr << "无法打开文件" << std::endl;
        return 1;
    }

    FILE* file_video_out = fopen("test_rtmp_hevc.bin", "wb");
    FILE* file_audio_out = fopen("testaudio_aac.bin", "wb");

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
    readPacket(file, 128, file_video_out, file_audio_out);

    //Window Acknowledgement Size
    readPacket(file, 128, file_video_out, file_audio_out);
    //Set Peer Bandwidth
    readPacket(file, 128, file_video_out, file_audio_out);

    //Set Chunk Size
    int chunk_size = readPacket(file, 128, file_video_out, file_audio_out);
    //_result
    readPacket(file, chunk_size, file_video_out, file_audio_out);
    //Set Chunk Size
    chunk_size = readPacket(file, chunk_size, file_video_out, file_audio_out);

    //releaseStream
    readPacket(file, chunk_size, file_video_out, file_audio_out);
    //FCPublish
    readPacket(file, chunk_size, file_video_out, file_audio_out);
    //createStream
    readPacket(file, chunk_size, file_video_out, file_audio_out);

    //_result
    readPacket(file, chunk_size, file_video_out, file_audio_out);
    //publish
    readPacket(file, chunk_size, file_video_out, file_audio_out);
    //_result
    //readPacket(file, chunk_size, file_video_out, file_audio_out);

    //onStatus
    readPacket(file, chunk_size, file_video_out, file_audio_out);

    //publish
    //readPacket(file, chunk_size, file_video_out, file_audio_out);

    //onStatus
    //readPacket(file, chunk_size, file_video_out, file_audio_out);

    //setDataFrame
    readPacket(file, chunk_size, file_video_out, file_audio_out);

    //video Data
    readPacket(file, chunk_size, file_video_out, file_audio_out);

    //audio Data
    readPacket(file, chunk_size, file_video_out, file_audio_out);

    while (!file.eof()) {
        readPacket(file, chunk_size, file_video_out, file_audio_out);
    }
    fclose(file_video_out);
    fclose(file_audio_out);
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
