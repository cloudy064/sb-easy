/* Grisu2 shortest double formatting, ported from nlohmann::json
 * (detail/conversions/to_chars.hpp, MIT, (c) 2009 Florian Loitsch / Niels
 * Lohmann) so sbj_dump() emits exactly the digits nlohmann produces. */
#include <stdint.h>
#include <string.h>

typedef struct { uint64_t f; int e; } diyfp;

static diyfp diy_sub(diyfp x, diyfp y) { diyfp r = {x.f - y.f, x.e}; return r; }

static diyfp diy_mul(diyfp x, diyfp y) {
    const uint64_t u_lo = x.f & 0xFFFFFFFFu, u_hi = x.f >> 32u;
    const uint64_t v_lo = y.f & 0xFFFFFFFFu, v_hi = y.f >> 32u;
    const uint64_t p0 = u_lo * v_lo, p1 = u_lo * v_hi, p2 = u_hi * v_lo, p3 = u_hi * v_hi;
    uint64_t Q = (p0 >> 32u) + (p1 & 0xFFFFFFFFu) + (p2 & 0xFFFFFFFFu);
    Q += (uint64_t)1 << 31u;
    diyfp r = {p3 + (p2 >> 32u) + (p1 >> 32u) + (Q >> 32u), x.e + y.e + 64};
    return r;
}

static diyfp diy_normalize(diyfp x) {
    while ((x.f >> 63u) == 0) { x.f <<= 1u; x.e--; }
    return x;
}

static diyfp diy_normalize_to(diyfp x, int e) {
    diyfp r = {x.f << (x.e - e), e};
    return r;
}

typedef struct { diyfp w, minus, plus; } boundaries;

static boundaries compute_boundaries(double value) {
    const int kPrecision = 53;
    const int kBias = 1024 - 1 + (kPrecision - 1);
    const int kMinExp = 1 - kBias;
    const uint64_t kHiddenBit = (uint64_t)1 << (kPrecision - 1);
    uint64_t bits;
    memcpy(&bits, &value, sizeof bits);
    const uint64_t E = bits >> (kPrecision - 1);
    const uint64_t F = bits & (kHiddenBit - 1);
    diyfp v;
    if (E == 0) { v.f = F; v.e = kMinExp; }
    else { v.f = F + kHiddenBit; v.e = (int)E - kBias; }
    const int lower_closer = F == 0 && E > 1;
    diyfp m_plus = {2 * v.f + 1, v.e - 1};
    diyfp m_minus;
    if (lower_closer) { m_minus.f = 4 * v.f - 1; m_minus.e = v.e - 2; }
    else { m_minus.f = 2 * v.f - 1; m_minus.e = v.e - 1; }
    boundaries b;
    b.plus = diy_normalize(m_plus);
    b.minus = diy_normalize_to(m_minus, b.plus.e);
    b.w = diy_normalize(v);
    return b;
}

enum { kAlpha = -60, kGamma = -32 };
typedef struct { uint64_t f; int e; int k; } cached_power;

static const cached_power kCachedPowers[79] = {
    {UINT64_C(0xAB70FE17C79AC6CA), -1060, -300},
    {UINT64_C(0xFF77B1FCBEBCDC4F), -1034, -292},
    {UINT64_C(0xBE5691EF416BD60C), -1007, -284},
    {UINT64_C(0x8DD01FAD907FFC3C), -980, -276},
    {UINT64_C(0xD3515C2831559A83), -954, -268},
    {UINT64_C(0x9D71AC8FADA6C9B5), -927, -260},
    {UINT64_C(0xEA9C227723EE8BCB), -901, -252},
    {UINT64_C(0xAECC49914078536D), -874, -244},
    {UINT64_C(0x823C12795DB6CE57), -847, -236},
    {UINT64_C(0xC21094364DFB5637), -821, -228},
    {UINT64_C(0x9096EA6F3848984F), -794, -220},
    {UINT64_C(0xD77485CB25823AC7), -768, -212},
    {UINT64_C(0xA086CFCD97BF97F4), -741, -204},
    {UINT64_C(0xEF340A98172AACE5), -715, -196},
    {UINT64_C(0xB23867FB2A35B28E), -688, -188},
    {UINT64_C(0x84C8D4DFD2C63F3B), -661, -180},
    {UINT64_C(0xC5DD44271AD3CDBA), -635, -172},
    {UINT64_C(0x936B9FCEBB25C996), -608, -164},
    {UINT64_C(0xDBAC6C247D62A584), -582, -156},
    {UINT64_C(0xA3AB66580D5FDAF6), -555, -148},
    {UINT64_C(0xF3E2F893DEC3F126), -529, -140},
    {UINT64_C(0xB5B5ADA8AAFF80B8), -502, -132},
    {UINT64_C(0x87625F056C7C4A8B), -475, -124},
    {UINT64_C(0xC9BCFF6034C13053), -449, -116},
    {UINT64_C(0x964E858C91BA2655), -422, -108},
    {UINT64_C(0xDFF9772470297EBD), -396, -100},
    {UINT64_C(0xA6DFBD9FB8E5B88F), -369, -92},
    {UINT64_C(0xF8A95FCF88747D94), -343, -84},
    {UINT64_C(0xB94470938FA89BCF), -316, -76},
    {UINT64_C(0x8A08F0F8BF0F156B), -289, -68},
    {UINT64_C(0xCDB02555653131B6), -263, -60},
    {UINT64_C(0x993FE2C6D07B7FAC), -236, -52},
    {UINT64_C(0xE45C10C42A2B3B06), -210, -44},
    {UINT64_C(0xAA242499697392D3), -183, -36},
    {UINT64_C(0xFD87B5F28300CA0E), -157, -28},
    {UINT64_C(0xBCE5086492111AEB), -130, -20},
    {UINT64_C(0x8CBCCC096F5088CC), -103, -12},
    {UINT64_C(0xD1B71758E219652C), -77, -4},
    {UINT64_C(0x9C40000000000000), -50, 4},
    {UINT64_C(0xE8D4A51000000000), -24, 12},
    {UINT64_C(0xAD78EBC5AC620000), 3, 20},
    {UINT64_C(0x813F3978F8940984), 30, 28},
    {UINT64_C(0xC097CE7BC90715B3), 56, 36},
    {UINT64_C(0x8F7E32CE7BEA5C70), 83, 44},
    {UINT64_C(0xD5D238A4ABE98068), 109, 52},
    {UINT64_C(0x9F4F2726179A2245), 136, 60},
    {UINT64_C(0xED63A231D4C4FB27), 162, 68},
    {UINT64_C(0xB0DE65388CC8ADA8), 189, 76},
    {UINT64_C(0x83C7088E1AAB65DB), 216, 84},
    {UINT64_C(0xC45D1DF942711D9A), 242, 92},
    {UINT64_C(0x924D692CA61BE758), 269, 100},
    {UINT64_C(0xDA01EE641A708DEA), 295, 108},
    {UINT64_C(0xA26DA3999AEF774A), 322, 116},
    {UINT64_C(0xF209787BB47D6B85), 348, 124},
    {UINT64_C(0xB454E4A179DD1877), 375, 132},
    {UINT64_C(0x865B86925B9BC5C2), 402, 140},
    {UINT64_C(0xC83553C5C8965D3D), 428, 148},
    {UINT64_C(0x952AB45CFA97A0B3), 455, 156},
    {UINT64_C(0xDE469FBD99A05FE3), 481, 164},
    {UINT64_C(0xA59BC234DB398C25), 508, 172},
    {UINT64_C(0xF6C69A72A3989F5C), 534, 180},
    {UINT64_C(0xB7DCBF5354E9BECE), 561, 188},
    {UINT64_C(0x88FCF317F22241E2), 588, 196},
    {UINT64_C(0xCC20CE9BD35C78A5), 614, 204},
    {UINT64_C(0x98165AF37B2153DF), 641, 212},
    {UINT64_C(0xE2A0B5DC971F303A), 667, 220},
    {UINT64_C(0xA8D9D1535CE3B396), 694, 228},
    {UINT64_C(0xFB9B7CD9A4A7443C), 720, 236},
    {UINT64_C(0xBB764C4CA7A44410), 747, 244},
    {UINT64_C(0x8BAB8EEFB6409C1A), 774, 252},
    {UINT64_C(0xD01FEF10A657842C), 800, 260},
    {UINT64_C(0x9B10A4E5E9913129), 827, 268},
    {UINT64_C(0xE7109BFBA19C0C9D), 853, 276},
    {UINT64_C(0xAC2820D9623BF429), 880, 284},
    {UINT64_C(0x80444B5E7AA7CF85), 907, 292},
    {UINT64_C(0xBF21E44003ACDD2D), 933, 300},
    {UINT64_C(0x8E679C2F5E44FF8F), 960, 308},
    {UINT64_C(0xD433179D9C8CB841), 986, 316},
    {UINT64_C(0x9E19DB92B4E31BA9), 1013, 324},
};

static cached_power get_cached_power(int e) {
    const int f = kAlpha - e - 1;
    const int k = ((f * 78913) / (1 << 18)) + (f > 0);
    const int index = (300 + k + (8 - 1)) / 8;
    return kCachedPowers[index];
}

static int find_largest_pow10(uint32_t n, uint32_t *pow10) {
    static const uint32_t p[] = {1000000000u, 100000000u, 10000000u, 1000000u, 100000u,
                                 10000u, 1000u, 100u, 10u};
    for (int i = 0; i < 9; ++i)
        if (n >= p[i]) { *pow10 = p[i]; return 10 - i; }
    *pow10 = 1;
    return 1;
}

static void grisu2_round(char *buf, int len, uint64_t dist, uint64_t delta, uint64_t rest, uint64_t ten_k) {
    while (rest < dist && delta - rest >= ten_k &&
           (rest + ten_k < dist || dist - rest > rest + ten_k - dist)) {
        buf[len - 1]--;
        rest += ten_k;
    }
}

static void grisu2_digit_gen(char *buffer, int *length, int *decimal_exponent, diyfp M_minus, diyfp w,
                             diyfp M_plus) {
    uint64_t delta = diy_sub(M_plus, M_minus).f;
    uint64_t dist = diy_sub(M_plus, w).f;
    const diyfp one = {(uint64_t)1 << -M_plus.e, M_plus.e};
    uint32_t p1 = (uint32_t)(M_plus.f >> -one.e);
    uint64_t p2 = M_plus.f & (one.f - 1);
    uint32_t pow10;
    int n = find_largest_pow10(p1, &pow10);
    while (n > 0) {
        const uint32_t d = p1 / pow10, r = p1 % pow10;
        buffer[(*length)++] = (char)('0' + d);
        p1 = r;
        n--;
        const uint64_t rest = ((uint64_t)p1 << -one.e) + p2;
        if (rest <= delta) {
            *decimal_exponent += n;
            grisu2_round(buffer, *length, dist, delta, rest, (uint64_t)pow10 << -one.e);
            return;
        }
        pow10 /= 10;
    }
    int m = 0;
    for (;;) {
        p2 *= 10;
        const uint64_t d = p2 >> -one.e, r = p2 & (one.f - 1);
        buffer[(*length)++] = (char)('0' + d);
        p2 = r;
        m++;
        delta *= 10;
        dist *= 10;
        if (p2 <= delta) break;
    }
    *decimal_exponent -= m;
    grisu2_round(buffer, *length, dist, delta, p2, one.f);
}

/* value finite and > 0. Writes digits (no NUL) and returns their count;
 * value == digits * 10^(*decimal_exponent). */
static int grisu2(char *buf, int *decimal_exponent, double value) {
    const boundaries b = compute_boundaries(value);
    const cached_power cached = get_cached_power(b.plus.e);
    const diyfp c_minus_k = {cached.f, cached.e};
    const diyfp w = diy_mul(b.w, c_minus_k);
    const diyfp w_minus = diy_mul(b.minus, c_minus_k);
    const diyfp w_plus = diy_mul(b.plus, c_minus_k);
    const diyfp M_minus = {w_minus.f + 1, w_minus.e};
    const diyfp M_plus = {w_plus.f - 1, w_plus.e};
    int len = 0;
    *decimal_exponent = -cached.k;
    grisu2_digit_gen(buf, &len, decimal_exponent, M_minus, w, M_plus);
    return len;
}
