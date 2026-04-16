#pragma once

#include <chrono>
#include <medida/metrics_registry.h>

namespace stellar
{
class MetricsRegistry : public medida::MetricsRegistry
{
  public:
    MetricsRegistry(std::chrono::seconds windowSize = std::chrono::seconds{30});
};
}
