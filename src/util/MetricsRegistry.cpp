#include "util/MetricsRegistry.h"

namespace stellar
{
MetricsRegistry::MetricsRegistry(std::chrono::seconds windowSize)
    : medida::MetricsRegistry(windowSize)
{
}
}
