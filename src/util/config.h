#pragma once
namespace PopulateOptions
{
enum class Options
{
    NONE = 0,
    PRESIZE = 1,
    DUMP = 2,
};

constexpr Options
operator&(Options a, Options b)
{
    return static_cast<Options>(static_cast<int>(a) & static_cast<int>(b));
}

constexpr Options
operator&(Options a, int b)
{
    return static_cast<Options>(static_cast<int>(a) & b);
}

constexpr Options
operator|(Options a, Options b)
{
    return static_cast<Options>(static_cast<int>(a) | static_cast<int>(b));
}

constexpr Options
operator|(Options a, int b)
{
    return static_cast<Options>(static_cast<int>(a) | b);
}

enum class DataEntriesType
{
    DEFAULT,
    LEDGER_ENTRY_LK_HASH,
    LEDGER_ENTRY_TO_OPAQUE_HASH,
    LEDGER_ENTRY_XDR_COMPUTE_HASH,
    OPAQUE_VEC,
    OPAQUE_VEC_XDR_HASH,
};

enum class Mode
{
    NORMAL,
    N_WAY_MERGE,
    N_WAY_MERGE_BUCKET_ENTRY_ID_CMP,
    ITERATE_BACKWARDS,
    ITERATE_PARALLEL,
};
} // namespace PopulateOptions
