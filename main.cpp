#include<iostream>
#include<cryptopp/md5.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;
using CryptoPP::ECIES;


#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
namespace ASN1 = CryptoPP::ASN1;


std::string encMe(AutoSeededRandomPool& R ,char* myData  , ECIES<ECP>::Encryptor pubKey ){
    std::string keyStr;
    std::string ivStr;
    std::string encKeyAndIv;
    std::string encMessage;
    std::string rawMd5;
    std::string encMd5;

//Create R with AES
    AutoSeededRandomPool prng;


    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP:: SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);


    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    CryptoPP:: CBC_Mode< CryptoPP::AES >::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);


//Encrypt R with public key



    StringSource s1(key.BytePtr(), key.size(), true,
                    new CryptoPP::HexEncoder(
                            new StringSink(keyStr)
                    ) // HexEncoder
    ); // StringSource




    std::cout<<"key is "<<std::endl<<keyStr<<std::endl;



    StringSource s2(iv.BytePtr(), iv.size(), true,
                    new CryptoPP::HexEncoder(
                            new StringSink(ivStr)
                    ) // HexEncoder
    ); // StringSource



    std::cout<<"iv is "<<ivStr<<std::endl;



    StringSource ss1 (std::string(keyStr +"/"+ ivStr), true, new PK_EncryptorFilter(R, pubKey, new StringSink(encKeyAndIv)) );

    std::cout<<"raw encrypted key and iv is "<<std::endl<<encKeyAndIv<<std::endl;




//Encrypt message with R
    StringSource s(myData, true, new CryptoPP::StreamTransformationFilter(enc,new StringSink(encMessage)));
    std::cout<<"raw enc message is "<<std::endl<<encMessage<<std::endl;




//encode our raw enc message and key

    std::string encodeEcnMessage;
    std::string encodeEncKey;





    StringSource s3((CryptoPP::byte*)&encMessage[0], encMessage.size(), true,
                    new CryptoPP::HexEncoder(
                            new StringSink(encodeEcnMessage)
                    ) // HexEncoder
    ); // StringSource


    std::cout<<"our encode encrypted message is "<<std::endl<<encodeEcnMessage<<std::endl;

    StringSource ss4((CryptoPP::byte*)&encKeyAndIv[0], encKeyAndIv.length(), true,
                     new CryptoPP::HexEncoder(
                             new StringSink(encodeEncKey)
                     ) // HexEncoder
    ); // StringSource


    std::cout<<"our encode encrypted key is "<<encodeEncKey<<std::endl;

//create format
    std::string myFormat =  encodeEncKey  +"/"+ encodeEcnMessage ;
    std::cout<<"our format is "<<std::endl<<myFormat<<std::endl;


//create MD5 out of our format




    CryptoPP::HexEncoder encodeMd5;
    CryptoPP::Weak1::MD5 hash;
    hash.Update((const CryptoPP::byte*)&myFormat[0], myFormat.size());
    rawMd5.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&rawMd5[0]);
    StringSource(rawMd5, true, new CryptoPP::Redirector(encodeMd5));


    std::cout<<"raw md5 is"<<std::endl<<rawMd5<<std::endl;


    StringSource s5((CryptoPP::byte*)&rawMd5[0], rawMd5.length(), true,
                    new CryptoPP::HexEncoder(
                            new StringSink(encMd5)
                    ) // HexEncoder
    ); // StringSource



    std::cout << "Hash md5 is: "<<encMd5<<std::endl;


    //return our output


    return  encMd5+myFormat;


}
void decMe(AutoSeededRandomPool& R , ECIES<ECP>::Decryptor pri , std::string str){
    //check the md5 hash
    std::string md5;
    std::string format;
    std::string encodedEncryptedMessage;
    std::string encodedEncryptedKeyAndIv;

    for(int a=0;a<=31;a++){

        md5 += str[a];

    }

    std::cout<<"md5 hash is ->" <<md5<<std::endl;
    for(int b=32;b<=str.length();b++){
        format+= str[b];
    }
    std::cout<<"format is -> "<<format<<std::endl;

    for(int c = 0;c<=format.length();c++){
        if(format[c] == '/'){
            break;
        }else{
            encodedEncryptedKeyAndIv += format[c];
        }
    }



    for(int d = format.length();d>=0;d--){
        if(format[d] == '/'){
            break;
        }else{
            encodedEncryptedMessage.insert(encodedEncryptedMessage.begin(),format[d]);
        }
    }





    //decrypt key and iv
    //decode key and iv
    std::string decodedEncryptedKeyAndIv;
    StringSource s1(encodedEncryptedKeyAndIv, true,
                    new CryptoPP::HexDecoder(
                            new StringSink(decodedEncryptedKeyAndIv)
                    )
    );

    //decrypt wiht our private key
    std::string decodeDecryptedKeyAndIv;
    StringSource ss2 (decodedEncryptedKeyAndIv, true, new PK_DecryptorFilter(R, pri, new StringSink(decodeDecryptedKeyAndIv) ) );

    std::string key;
    std::string iv;

    for(int e = 0;e<=decodeDecryptedKeyAndIv.length();e++){
        if(decodeDecryptedKeyAndIv[e] == '/'){
            break;
        }else{
            key+= decodeDecryptedKeyAndIv[e];
        }
    }
    for(int f = decodeDecryptedKeyAndIv.length() ; f>=0 ; f--){
        if(decodeDecryptedKeyAndIv[f] == '/'){
            break;
        }else{
            iv.insert(iv.begin(),decodeDecryptedKeyAndIv[f]);
        }
    }




    std::string decodedEncryptedMessage;
    StringSource s2(encodedEncryptedMessage, true,
                    new CryptoPP::HexDecoder(
                            new StringSink(decodedEncryptedMessage)
                    )
    );


    std::string decodeKey;
    std::string decodeIv;

    StringSource s3(key, true,
                    new CryptoPP::HexDecoder(
                            new StringSink(decodeKey)
                    )
    );
    StringSource s4(iv, true,
                    new CryptoPP::HexDecoder(
                            new StringSink(decodeIv)
                    )
    );





    std::string message;



    CryptoPP:: CBC_Mode< CryptoPP::AES >::Decryption dec;
    dec.SetKeyWithIV((CryptoPP::byte*)&decodeKey[0], 16, (CryptoPP::byte*)&decodeIv[0]);


    StringSource s(decodedEncryptedMessage, true,
                   new CryptoPP::StreamTransformationFilter(dec,
                                                            new StringSink(message)
                   ) // StreamTransformationFilter
    ); // StringSource


    std::cout<<"message is->"<<message;


}




int main()
{

    char* myMessage = "Hi";
    AutoSeededRandomPool R;
    ECIES<ECP>::Decryptor pri(R, ASN1::secp256r1());
    ECIES<ECP>::Encryptor pub(pri);
    std::string outPut = encMe(R,myMessage,pub);
    std::cout<<"-------------------------------------------dec func -------------------------------"<<std::endl;
    decMe(R,pri,outPut);



}
