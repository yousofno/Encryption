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

CryptoPP::HexEncoder keyEncoder;
keyEncoder.Put(key,key.size());
keyEncoder.MessageEnd();

CryptoPP:: word64 size = keyEncoder.MaxRetrievable();
    if(size)
    {
        keyStr.resize(size);
        keyEncoder.Get((CryptoPP::byte*)&keyStr[0], keyStr.size());
    }

    std::cout<<"key is "<<keyStr<<std::endl;


    CryptoPP::HexEncoder ivEncoder;
    ivEncoder.Put(iv,iv.size());
    ivEncoder.MessageEnd();

    CryptoPP:: word64 size2 = ivEncoder.MaxRetrievable();
    if(size2)
    {
        ivStr.resize(size2);
        ivEncoder.Get((CryptoPP::byte*)&ivStr[0], ivStr.size());
    }

    std::cout<<"iv is "<<ivStr<<std::endl;



    StringSource ss1 (std::string(keyStr + ivStr), true, new PK_EncryptorFilter(prng, pubKey, new StringSink(encKeyAndIv)) );

    std::cout<<"raw encrypted key and iv is "<<std::endl<<encKeyAndIv<<std::endl;


//Encrypt message with R
    StringSource s(myData, true, new CryptoPP::StreamTransformationFilter(enc,new StringSink(encMessage)));
    std::cout<<"raw enc message is "<<std::endl<<encMessage<<std::endl;





//encode our raw enc message and key

std::string encodeEcnMessage;
std::string encodeEncKey;



    CryptoPP::HexEncoder encodeMessage;
    encodeMessage.Put((CryptoPP::byte*)&encMessage[0],encMessage.size());
    encodeMessage.MessageEnd();
    CryptoPP:: word64 size3 = encodeMessage.MaxRetrievable();
    if(size3)
    {
        encodeEcnMessage.resize(size);
        encodeMessage.Get((CryptoPP::byte*)&encodeEcnMessage[0], encodeEcnMessage.size());
    }

std::cout<<"our encode encrypted message is "<<std::endl<<encodeEcnMessage<<std::endl;




    CryptoPP::HexEncoder encodedKey;
    encodedKey.Put((CryptoPP::byte*)&encKeyAndIv[0],encKeyAndIv.size());
    encodedKey.MessageEnd();
    CryptoPP:: word64 size4 = encodedKey.MaxRetrievable();
    if(size4)
    {
        encodeEncKey.resize(size);
        encodedKey.Get((CryptoPP::byte*)&encodeEncKey[0], encodeEncKey.size());
    }

    std::cout<<"our encode encrypted key is "<<std::endl<<encodeEncKey<<std::endl;







//create format
std::string myFormat =  std::to_string(encodeEncKey.length()) +encodeEncKey + std::to_string(encodeEcnMessage.length()) + encodeEcnMessage ;
std::cout<<"our format is "<<std::endl<<myFormat<<std::endl;


//create MD5 out of our format




    CryptoPP::HexEncoder encodeMd5;
    CryptoPP::Weak1::MD5 hash;
    hash.Update((const CryptoPP::byte*)&myFormat[0], myFormat.size());
    rawMd5.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&rawMd5[0]);
    StringSource(rawMd5, true, new CryptoPP::Redirector(encodeMd5));


    std::cout<<"raw md5 is"<<std::endl<<rawMd5<<std::endl;
    encodeMd5.Put((CryptoPP::byte*)&rawMd5[0],rawMd5.size());
    encodeMd5.MessageEnd();
    CryptoPP:: word64 size5 = encodeMd5.MaxRetrievable();
    if(size5)
    {
        encMd5.resize(size);
        encodeMd5.Get((CryptoPP::byte*)&encMd5[0], encMd5.size());
    }
 std::cout << "Hash md5 is: "<<encMd5<<std::endl;


    //return our output


    return "our output is " + encMd5+myFormat;


}
void decMe(){





}


int main()
{

    char* myMessage = "Hello world";
    AutoSeededRandomPool R;
    ECIES<ECP>::Decryptor pri(R, ASN1::secp256r1());
    ECIES<ECP>::Encryptor pub(pri);
    std::cout<<encMe(R,myMessage,pub);







}