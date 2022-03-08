#include <iostream>
#include <fstream>
#include <list>
#include <stdint.h>
#include <string>

using namespace std;

int PESL{};
int L{};
bool finished{};

//file
std::string fn = "PID136.mp2";
std::ofstream saveFile("PID136.mp2", std::ios::out | std::ios::binary);

class TS;

class Header
{
    int SB{ 47 };   //8b
    int E;          //1b
    int S;          //1b
    int P;          //1b
    int PID;        //13b
    int TSC;        //2b   
    int AFC;        //2b
    int CC;         //4b

public:
    Header() {};
    Header(uint8_t* tab)
    {
        uint8_t mask{ 0x80 };
        SB = tab[0];
        E = (bool)(tab[1] & mask);
        mask >>= 1;
        S = (bool)(tab[1] & mask);
        mask >>= 1;
        P = (bool)(tab[1] & mask);
        mask = 0x1F;
        PID = tab[1] & mask;
        PID <<= 8;
        mask = 0xFF;
        PID = PID | tab[2] & mask;
        mask = 0xC0;
        TSC = tab[3] & mask;
        TSC >>= 6;
        mask >>= 2;
        AFC = tab[3] & mask;
        AFC >>= 4;
        mask = 0x0F;
        CC = tab[3] & mask;

    }
    friend class TS;
    friend ostream& operator <<(ostream& out, Header ramka);
    friend ostream& operator <<(ostream& out, TS ramka);
};

class AF
{
    int AFL = -1;
    int DC;
    int RA;
    int SP_1;
    int PR;
    int OR;
    int SP_2;
    int TP;
    int EX;
    int Stuffing;
public:

    AF();
    AF(uint8_t* tab, int isAF)
    {
        if (isAF > 1)
        {
            AFL = tab[4];
            uint8_t mask = 0x01;
            EX = tab[5] & mask;
            mask <<= 1;
            TP = tab[5] & mask;
            mask <<= 1;
            SP_2 = tab[5] & mask;
            mask <<= 1;
            OR = tab[5] & mask;
            mask <<= 1;
            PR = tab[5] & mask;
            mask <<= 1;
            SP_1 = tab[5] & mask;
            mask <<= 1;
            RA = tab[5] & mask;
            mask <<= 1;
            DC = tab[5] & mask;
            Stuffing = AFL - 1;
        }
    }
    friend class TS;
    friend ostream& operator <<(ostream& out, AF ramka);
    friend ostream& operator <<(ostream& out, TS ramka);
};

class PES
{
    int PSCP;   //24b
    int SID;    //8b
    int L{ 0 };      //16b
    //opcional
    bool extension{ 0 };
    int lenght;
    int PTS;
    int DTS;
    int ESCR;

    int SC;
    int P;
    int DAI;
    int C;
    int OoC;
    int PTSFlags;
    int DTSFlags;
    int ESCRFlag;
    int ESRateFlag;
    int DSMtmf;
    int additionalCopyInfoFlag;
    int PESCRCFlag;
    int PESExtensionFlag;
    int headerDataL;

    PES();
    PES(uint8_t* tab, int size)
    {
        //uint8_t mask = 0x01;
        PSCP = tab[size];
        PSCP <<= 8;
        PSCP |= tab[size + 1];
        PSCP <<= 8;
        PSCP |= tab[size + 2];

        SID = tab[size + 3];

        L = tab[size + 4];
        L <<= 8;
        L += tab[size + 5];

        lenght = 6;

        if (SID != 0xBC && SID != 0xBE && SID != 0xBF && SID != 0xF0
            && SID != 0xF1 && SID != 0xFF && SID != 0xF2 && SID != 0xF8)
        {
            lenght += 3;

            uint8_t mask = 0x30;
            SC = tab[size + 6] & mask;
            SC >>= 4;

            mask = 0x08;
            P = (bool)(tab[size + 6] & mask);

            mask >>= 1;
            DAI = (bool)(tab[size + 6] & mask);

            mask >>= 1;
            C = (bool)(tab[size + 6] & mask);

            mask >>= 1;
            OoC = (bool)(tab[size + 6] & mask);

            mask = 0x80;
            PTSFlags = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            DTSFlags = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            ESCRFlag = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            ESRateFlag = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            DSMtmf = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            additionalCopyInfoFlag = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            PESCRCFlag = (bool)(tab[size + 7] & mask);

            mask >>= 1;
            PESExtensionFlag = (bool)(tab[size + 7] & mask);

            headerDataL = tab[size + 8];

            //PTS || DTS
            if (PTSFlags)
            {
                uint8_t mask = 0x0E;
                PTS = tab[size + lenght] & mask;
                PTS <<= 7;
                PTS |= tab[size + lenght + 1];
                PTS <<= 8;
                mask = 0xFE;
                PTS |= tab[size + lenght + 2] & mask;
                PTS <<= 7;
                PTS |= tab[size + lenght + 3];
                PTS <<= 8;
                PTS |= tab[size + lenght + 4] & mask;
                PTS >>= 1;

                lenght += 5;
            }
            if (DTSFlags)
            {
                uint8_t mask = 0x0E;
                DTS = tab[size + lenght] & mask;
                DTS <<= 7;
                DTS |= tab[size + lenght + 1];
                DTS <<= 8;
                mask = 0xFE;
                DTS |= tab[size + lenght + 2] & mask;
                DTS <<= 7;
                DTS |= tab[size + lenght + 3];
                DTS <<= 8;
                DTS |= tab[size + lenght + 4] & mask;
                DTS >>= 1;

                lenght += 5;
            }
            if (ESCRFlag)
                lenght += 6;
            if (ESRateFlag)
                lenght += 3;
            if (additionalCopyInfoFlag)
                lenght++;
            if (PESCRCFlag)
                lenght += 2;
            if (PESExtensionFlag)
            {
                int tmp = ++lenght;
                if (tab[size + tmp] & 0x01)
                    lenght += 2;
                if (tab[size + tmp] & 0x20)
                    lenght += 2;
                if (tab[size + tmp] & 0x10)
                    lenght++;
                if (tab[size + tmp] & 0x80)
                    lenght += 2;
                if (tab[size + tmp] & 0x40)
                    lenght++;
            }
        }

        //lenght = 14;
    }

    friend class TS;
    friend ostream& operator <<(ostream& out, PES ramka);
    friend ostream& operator <<(ostream& out, TS ramka);
};

class TS
{
    Header header;
    AF af;
    PES pes;
    int size;

public:
    TS();
    TS(uint8_t* tab) : header(tab), af(tab, header.AFC), pes(tab, af.AFL + 5)
    {
        if (header.S && header.PID == 136 && header.AFC > 1)
        {
            pes = PES(tab, (af.AFL + 5));
            PESL = 0;
            L = pes.L;

            save(tab, (5 + af.AFL + pes.lenght));

        }
        else if (header.PID == 136 && header.S == 0 && header.AFC < 2)
        {
            save(tab, 4);
        }
        else if (header.PID == 136 && header.S == 0)
        {
            save(tab, 5 + af.AFL);
        }
        if (header.AFC < 2 && header.PID == 136)
            PESL += (188 - 4);
        else if (header.PID == 136)
            PESL += (188 - 5 - af.AFL);


    }
    void save(uint8_t* tab, int start)
    {
        for (int i = start; i < 188; i++)
        {
            uint8_t tmp = tab[i];
            saveFile << tmp;
        }

    }
    friend ostream& operator <<(ostream& out, TS ramka);
    friend class AF;
};

ostream& operator <<(ostream& out, Header ramka)
{
    out << " TS: SB = " << ramka.SB << " E = " << ramka.E << " S = " << ramka.S << " P = " << ramka.P << " PID = "
        << ramka.PID << " TSC = " << ramka.TSC << " AFC = " << ramka.AFC << " CC = " << ramka.CC;
    return out;
}

ostream& operator <<(ostream& out, AF ramka)
{
    out << " AF: L = " << ramka.AFL << " DC = " << ramka.DC << " RA = " << ramka.RA << " SP = " << ramka.SP_1
        << " PR = " << ramka.PR << " OR = " << ramka.OR << " SP = " << ramka.SP_2 << " TP = "
        << ramka.TP << " EX = " << ramka.EX; //<< " Stuffing = " <<ramka.Stuffing;
    return out;
}

ostream& operator <<(ostream& out, PES ramka)
{
    out << endl << " PES: PSCP = " << ramka.PSCP << " SID = " << ramka.SID << " L = " << ramka.L;
    if (ramka.PTSFlags)
        out << " PTS = " << ramka.PTS;
    if (ramka.DTSFlags)
        out << " PTS = " << ramka.DTS;
    //out << endl;
    return out;
}

ostream& operator <<(ostream& out, TS ramka)
{
    bool end = 0;

    out << ramka.header << " ";
    if (ramka.header.PID == 136)
    {
        if (ramka.header.S)
        {
            finished = 0;
            out << "Started ";
            out << PESL;
        }
        else if (PESL < L)
        {
            out << "Continue ";
            out << PESL;
        }
        else
        {
            if (!finished)
            {
                out << "Finished ";
                finished = 1;
                end = 1;
                out << PESL;
            }
        }
        out << endl;
    }
    if (ramka.header.AFC > 1)
        out << ramka.af << " ";
    if (ramka.header.S)
        out << ramka.pes << " ";
    else if (end)
    {
        out << endl << " PES: Len = " << PESL << " PcktLen = " << ramka.pes.lenght << " DataLen = " << (PESL - ramka.pes.lenght);
    }
    //out << endl;
    return out;
}

int main()
{
    std::string fileName = "example_new.ts";
    std::ifstream file("example_new.ts", std::ios::in | std::ios::binary);

    int b{}, counter{}, i{};
    uint8_t tab[188]{};
    list<TS> strumien;

    while (!file.eof())
    {
        tab[i] = file.get();

        if (i == 187)
        {
            TS element(tab);
            strumien.push_back(element);
            cout << counter++ << " " << element << endl;
            //cout << i << " " << tab[0] << " " <<tab[1]<<" "<<tab[2]<<" " <<tab[3] << endl;
        }

        i++;
        i %= 188;
    }

    saveFile.close();
}
