#include <string>
#include <ios>
#include <iostream>
#include <fstream>
#include <string.h>
#include <stdarg.h>

#define LUA51_SIGNATURE "\033Lua"
#define LUA51_VERSION 0x51

struct lua51_header {
    uint8_t magic[4];
    uint8_t version;
    uint8_t format;
    uint8_t endian;
    uint8_t sizeof_int;
    uint8_t sizeof_size_t;
    uint8_t sizeof_insn;
    uint8_t sizeof_lua_number;
    uint8_t flag;
} __attribute__((packed));

/*
 * OpenWrt patch:
 *   https://github.com/openwrt/openwrt/blob/openwrt-19.07/package/utils/lua/patches
 */

#define LUAXQ_SIGNATURE "\033Fate/Z\033"
#define LUAXQ_VERSION 0x51
#define LUAXQ_FORMAT 0
#define LUAXQ_ENDIAN 1
#define LUAXQ_SIZEOF_INT 4
#define LUAXQ_SIZEOF_UINT 4
#define LUAXQ_SIZEOF_INSN 4
#define LUAXQ_SIZEOF_LUA_NUMBER 8
#define LUAXQ_SIZEOF_LUA_INTEGER 4

struct luaxq_header {
    uint8_t magic[8];
    uint8_t version;
    uint8_t format;
    uint8_t endian;
    uint8_t sizeof_int;
    uint8_t sizeof_uint;
    uint8_t sizeof_insn;
    uint8_t sizeof_lua_number;
    uint8_t sizeof_lua_integer;
} __attribute__((packed));

#define LUA51_TNIL 0
#define LUA51_TBOOLEAN 1
#define LUA51_TNUMBER 3
#define LUA51_TSTRING 4
#define LUA51_TFUNCTION 6

/* Xiaomi modification. */
#define LUAXQ_TNIL 3
#define LUAXQ_TBOOLEAN 4
#define LUAXQ_TNUMBER 6
#define LUAXQ_TSTRING 7
#define LUAXQ_TFUNCTION 6
#define LUAXQ_TINT 12

/* LUA 5.1.5 opcodes */
enum {
    OP_MOVE,        // 0
    OP_LOADK,       //
    OP_LOADBOOL,    //
    OP_LOADNIL,     //
    OP_GETUPVAL,    //
    OP_GETGLOBAL,   //
    OP_GETTABLE,    //
    OP_SETGLOBAL,   //
    OP_SETUPVAL,    // 8
    OP_SETTABLE,    //
    OP_NEWTABLE,    //
    OP_SELF,        //
    OP_ADD,         //
    OP_SUB,         //
    OP_MUL,         //
    OP_DIV,         //
    OP_MOD,         // 0x10
    OP_POW,         //
    OP_UNM,         //
    OP_NOT,         //
    OP_LEN,         //
    OP_CONCAT,      //
    OP_JMP,         //
    OP_EQ,          //
    OP_LT,          // 0x18
    OP_LE,          //
    OP_TEST,        //
    OP_TESTSET,     //
    OP_CALL,        //
    OP_TAILCALL,    //
    OP_RETURN,      //
    OP_FORLOOP,     //
    OP_FORPREP,     // 0x20
    OP_TFORLOOP,    //
    OP_SETLIST,     //
    OP_CLOSE,       //
    OP_CLOSURE,     //
    OP_VARARG,      //
};

#ifdef DEBUG_PRINT_INSN
static const char *gOpName[] = {
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL",
    "GETUPVAL", "GETGLOBAL", "GETTABLE", "SETGLOBAL",
    "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF",
    "ADD", "SUB", "MUL", "DIV",
    "MOD", "POW", "UNM", "NOT",
    "LEN", "CONCAT", "JMP", "EQ",
    "LT", "LE", "TEST", "TESTSET",
    "CALL", "TAILCALL", "RETURN", "FORLOOP",
    "FORPREP", "TFORLOOP", "SETLIST", "CLOSE",
    "CLOSURE", "VARARG",
};
#endif

/* Xiaomi modification. */

#define OP_ESCAPE 0xffff

static const int gXQOp[] = {
    OP_LEN, OP_CLOSURE, OP_ESCAPE, OP_LT,           // 0
    OP_NOT, OP_LT, OP_LOADK, OP_SETLIST,            // 4
    OP_RETURN, OP_TEST, OP_TFORLOOP, OP_FORPREP,    // 8
    OP_SUB, OP_TAILCALL, OP_DIV, OP_SELF,           // 0xc
    OP_CALL, OP_SETTABLE, OP_GETUPVAL, OP_EQ,       // 0x10
    OP_EQ, OP_CONCAT, OP_LE, OP_LE,                 // 0x14
    OP_LOADBOOL, OP_MOD, OP_FORLOOP, OP_GETTABLE,   // 0x18
    OP_NEWTABLE, OP_CLOSE, OP_VARARG, OP_JMP,       // 0x1c
    OP_UNM, OP_POW, OP_MUL, OP_TESTSET,             // 0x20
    OP_MOVE, OP_ADD, OP_GETGLOBAL, OP_SETUPVAL,     // 0x24
    OP_SETGLOBAL, OP_LOADNIL,                       // 0x28
};

class XQLuaC {
    public:
        XQLuaC(const char* in, const char* out);
        ~XQLuaC();
        int convert(void);

    private:
        bool readHeader(void);
        char readChar(void);
        int readInt(void);
        double readDouble(void);
        std::string readString(void);
        char *readData(size_t size);

        void writeHeader(void);
        void writeChar(char val);
        void writeInt(int val);
        void writeDouble(double val);
        void writeString(std::string& val);
        void writeData(const char *data, size_t size);

        int convertFunction(void);
        int convertConstants(void);
        int convertDebug(void);

    private:
        std::ifstream *ifd;
        std::ofstream *ofd;
};

static void msg(const char *fmt, ...)
{
    va_list ap;
    char *str = NULL;

    va_start(ap, fmt);
    ::vasprintf(&str, fmt, ap);
    std::string msg = str;
    ::free(str);
    std::cout << msg;
    va_end(ap);
}

XQLuaC::XQLuaC(const char* in, const char* out)
{
    ifd = new std::ifstream(in, std::ios::in|std::ios::binary);
    ofd = new std::ofstream(out, std::ios::out|std::ios::trunc|std::ios::binary);
}

XQLuaC::~XQLuaC()
{
    delete ofd;
    delete ifd;
}

bool XQLuaC::readHeader(void)
{
    char data[sizeof(struct luaxq_header)];
    struct luaxq_header *h;

    ifd->read(data, sizeof(data));
    if (data[0] == '#' && data[1] == '!') {
        bool ok = false;
        char ch;
        ifd->seekg(0, ifd->beg);
        while (ifd->get(ch)) {
            if (ch == '\n') {
                ok = true;
                break;
            }
        }
        if (!ok) {
            return -1;
        }
        ifd->read(data, sizeof(data));
    }
    h = (struct luaxq_header *) data;
    if (::memcmp(h->magic, LUAXQ_SIGNATURE, 8))
        return false;
    if (h->version != LUAXQ_VERSION)
        return false;
    if (h->format != LUAXQ_FORMAT)
        return false;
    if (h->endian != LUAXQ_ENDIAN)
        return false;
    if (h->sizeof_int != LUAXQ_SIZEOF_INT)
        return false;
    if (h->sizeof_uint != LUAXQ_SIZEOF_UINT)
        return false;
    if (h->sizeof_insn != LUAXQ_SIZEOF_INSN)
        return false;
    if (h->sizeof_lua_number != LUAXQ_SIZEOF_LUA_NUMBER)
        return false;
    if (h->sizeof_lua_integer != LUAXQ_SIZEOF_LUA_INTEGER)
        return false;
    return true;
}

char XQLuaC::readChar(void)
{
    char data[1];

    ifd->read(data, 1);
    return data[0];
}

int XQLuaC::readInt(void)
{
    char data[4];

    ifd->read(data, 4);
    return (((data[3] & 0xff) << 24) | ((data[2] & 0xff) << 16) |
        ((data[1] & 0xff) << 8) | (data[0] & 0xff));
}

double XQLuaC::readDouble(void)
{
    char data[sizeof(double)];
    double dval;

    ifd->read(data, sizeof(data));
    ::memcpy(&dval, data, sizeof(dval));
    return dval;
}

std::string XQLuaC::readString(void)
{
    int size = readInt();
    if (size == 0)
        return std::string("");
    char *data = new char[size];
    ifd->read(data, size);
    /* Xiaomi modification. */
    char pass = (char)(size * 13 + 55);
    for (int i = 0; i < size; i++)
        data[i] ^= pass;
    return std::string(data);
}

char *XQLuaC::readData(size_t size)
{
    char *data = new char[size];
    ifd->read(data, size);
    return data;
}

void XQLuaC::writeHeader(void)
{
    char data[sizeof(struct lua51_header)];
    struct lua51_header *h = (struct lua51_header *) data;
    int x = 1;

    ::memcpy(h->magic, LUA51_SIGNATURE, sizeof(h->magic));
    h->version = LUA51_VERSION;
    h->format = 0;
    ::memcpy(&h->endian, &x, 1);
    h->sizeof_int = sizeof(int);
    h->sizeof_size_t = sizeof(size_t);
    h->sizeof_insn = sizeof(int32_t);
    h->sizeof_lua_number = sizeof(double);
    h->flag = 0;
    ofd->write(data, sizeof(data)); 
}

void XQLuaC::writeChar(char val)
{
    ofd->write(&val, 1);
}

void XQLuaC::writeInt(int val)
{
    char data[sizeof(val)];

    ::memcpy(data, &val, sizeof(data));
    ofd->write(data, sizeof(data));
}

void XQLuaC::writeDouble(double val)
{
    char data[sizeof(val)];

    ::memcpy(data, &val, sizeof(data));
    ofd->write(data, sizeof(data));
}

void XQLuaC::writeString(std::string& val)
{
    size_t slen = val.length();
    if (slen) {
        slen += 1;
        ofd->write((char *)&slen, sizeof(slen));
        ofd->write(val.c_str(), slen);
    } else {
        ofd->write((char *)&slen, sizeof(slen));
    }
}

void XQLuaC::writeData(const char *data, size_t size)
{
    ofd->write(data, size);
}

int XQLuaC::convertFunction(void)
{
    /* Xiaomi modification. */
    char argc = readChar();
    std::string fn = readString();
    char nups = readChar();
    int lnd = readInt();
    char va = readChar();
    int lln = readInt();
    char stack = readChar();
    /* Original serializtion order. */
    writeString(fn);
    writeInt(lnd);
    writeInt(lln);
    writeChar(nups);
    writeChar(argc);
    writeChar(va);
    writeChar(stack);
    /* code */
    int ret = 0;
    int nr_insn = readInt();
    writeInt(nr_insn);
    char *dt_insn = readData(nr_insn * sizeof(uint32_t));
#ifdef DEBUG_PRINT_INSN
    msg("<=== CODE %u ====\n", lnd);
#endif
    for (int i = 0; i < nr_insn; i++) {
        uint32_t insn = *((uint32_t *)(dt_insn + i * sizeof(insn)));
#ifdef DEBUG_PRINT_INSN
        msg("%d 0x%08x\n", i, insn);
#endif
        long offset = (long)ifd->tellg() + (i - nr_insn) * sizeof(insn);
        uint32_t op = insn & 0x3f;
        if (op >= sizeof(gXQOp)/sizeof(gXQOp[0])) {
            msg("Could not decode INSN 0x%08x at offset 0x%lx\n", insn, offset);
            ret = -1;
            break;
        }
        op = gXQOp[op];
        if (op == OP_ESCAPE) {
            op = (insn >> 14) & 0x1ff;
            if (op == 0)
                op = OP_CLOSE;
            else if (op == 1)
                op = OP_LEN;
            else if (op == 2)
                op = OP_UNM;
            else if (op == 3)
                op = OP_NOT;
            else {
                msg("Could not decode OP_ESCAPE 0x%08x at offset 0x%lx\n", insn, offset);
                ret = -1;
                break;
            }
#ifdef DEBUG_PRINT_INSN
            msg("%d Escaped INSN: 0x%08x at offset 0x%lx\n", i, insn, offset);
#endif
            insn &= ~(3 << 14);
        }
        // TODO: OP_EQ and so on needs to xchg register?
#ifdef DEBUG_PRINT_INSN
        msg("%d %s\n", i, gOpName[op]);
#endif
        insn &= 0xffffffc0u;
        insn |= op;
        *((uint32_t *)(dt_insn + i * sizeof(insn))) = insn;
    }
#ifdef DEBUG_PRINT_INSN
    msg("==== CODE %u ===>\n", lnd);
#endif
    writeData(dt_insn, nr_insn * sizeof(uint32_t));
    delete[] dt_insn;
    if (ret < 0)
        return ret;
    /* constants */
    ret = convertConstants();
    if (ret < 0)
        return ret;
    /* debug */
    ret = convertDebug();
    if (ret < 0)
        return ret;
    return 0;
}

int XQLuaC::convertConstants(void)
{
    int nr_val = readInt();
    writeInt(nr_val);
    for (int i = 0; i < nr_val; i++) {
        char type = readChar();
        switch (type) {
            case LUAXQ_TNIL:
                type = LUA51_TNIL;
                writeChar(type);
                break;
            case LUAXQ_TBOOLEAN: {
                type = LUA51_TBOOLEAN;
                writeChar(type);
                char val = readChar();
                writeChar(val);
                break;
            }
            case LUAXQ_TNUMBER: {
                type = LUA51_TNUMBER;
                writeChar(type);
                double val = readDouble();
                writeDouble(val);
                break;
            }
            case LUAXQ_TSTRING: {
                type = LUA51_TSTRING;
                writeChar(type);
                std::string val = readString();
                writeString(val);
                break;
            }
            case LUAXQ_TINT: {
                type = LUA51_TNUMBER;
                writeChar(type);
                int val = readInt();
                // XXX: Does this affect addressing?
                writeDouble((double)(val));
                break;
            }
            default: {
                msg("Could not decode constant at offset 0x%lx\n", (long)ifd->tellg());
                return -1;
            }
        }
    }
    int nr_func = readInt();
    writeInt(nr_func);
    for (int i = 0; i < nr_func; i++) {
        int ret = convertFunction();
        if (ret < 0)
            return ret;
    }
    return 0;
}

int XQLuaC::convertDebug(void)
{
    /* line info */
    int nr = readInt();
    writeInt(nr);
    if (nr) {
        for (int i = 0; i < nr; i++) {
            int val = readInt();
            writeInt(val);
        }
    }
    /* local variables */
    nr = readInt();
    writeInt(nr);
    if (nr) {
        for (int i = 0; i < nr; i++) {
            std::string name = readString();
            writeString(name);
            int start_pc = readInt();
            writeInt(start_pc);
            int end_pc = readInt();
            writeInt(end_pc);
        }
    }
    /* up values */
    nr = readInt();
    writeInt(nr);
    if (nr) {
        for (int i = 0; i < nr; i++) {
            std::string val = readString();
            writeString(val);
        }
    }
    return 0;
}

int XQLuaC::convert(void)
{
    if (!readHeader())
        return -1;
    writeHeader();
    if (convertFunction())
        return -1;
    /* See if there are still things left. */
    char ch;
    if (ifd->get(ch)) {
        msg("Could not fully read, consumed 0x%lx bytes\n",
            (long)ifd->tellg());
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
        return -1;
    XQLuaC xq(argv[1], argv[2]);
    return xq.convert();
}
