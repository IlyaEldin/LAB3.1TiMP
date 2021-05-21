#include <UnitTest++/UnitTest++.h>
#include </home/ilya/Lab1/Lab1/modAlphaCipher.h>
#include </home/ilya/Lab1/Lab1/modAlphaCipher.cpp>
#include </home/ilya/Lab1/Lab12/CesarDop.h>
#include </home/ilya/Lab1/Lab12/CesarDop.cpp>

string wstost (const wstring ws1) //переводит широкую строку в обычную для использования макроса CHECK_EQUAL
{
    const string a1( ws1.begin(), ws1.end() );
    return a1;
}

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL(wstost(modAlphaCipher(L"BCDEFGHIJK").encrypt(L"AAAAA")),wstost(L"BCDEF"));
    }
    TEST(LongKey) {
        CHECK_EQUAL(wstost(L"BCDEF"),wstost(modAlphaCipher(L"BCDEFGHIJK").encrypt(L"AAAAA")));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL(wstost(L"BCDBC"),wstost(modAlphaCipher(L"bcd").encrypt(L"AAAAA")));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher(L"B1"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher(L"B,C"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher(L"B  C"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher(L""),cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher(L"AAA"),cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher * p;
    KeyB_fixture()    {
        p = new modAlphaCipher(L"B");
    }    ~KeyB_fixture()    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH",wstost(
                        p->encrypt(L"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH",
                    wstost(p->encrypt(L"thequickbrownfoxjumpsoverthelazydog")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH",
                    wstost(p->encrypt(L"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG!!!")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("IBQQZOFXZFBS",
                    wstost(p->encrypt(L"Happy New 2021 Year")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(wstost(p->encrypt(L"")),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(wstost(p->encrypt(L"1234+8765=9999")),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("SGDPTHBJAQNVMENWITLORNUDQSGDKZYXCNF", wstost(modAlphaCipher(L"Z").encrypt(L"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
                      wstost(p->decrypt(L"UIFRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"uifRVJDLCSPXOGPYKVNQTPWFSUIFMBAZEPH"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"UIF RVJDL CSPXO GPY KVNQT PWFS UIF MBAZ EPH"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"IBQQZOFX2019ZFBS"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"IFMMP,XPSME"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
wstost(modAlphaCipher(L"Z").decrypt(L"SGDPTHBJAQNVMENWITLORNUDQSGDKZYXCNF")));
    }
}



int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
