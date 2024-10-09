// Copyright(c) 2015-present, Gabi Melman & spdlog contributors.
// Distributed under the MIT License (http://opensource.org/licenses/MIT)

#pragma once

#ifdef __OHOS__

    #include <spdlog/details/fmt_helper.h>
    #include <spdlog/details/null_mutex.h>
    #include <spdlog/details/os.h>
    #include <spdlog/details/synchronous_factory.h>
    #include <spdlog/sinks/base_sink.h>

    #include <hilog/log.h>
    #include <mutex>
    #include <string>

namespace spdlog {
namespace sinks {

/*
 * hilog sink for OHOS
 *
 * link against libhilog_ndk.z.so
 */
template <typename Mutex>
class ohos_hilog_sink final : public base_sink<Mutex> {
public:
    explicit ohos_hilog_sink(std::string tag = "spdlog_ohos",
                             unsigned int domain = 0x000A,
                             bool use_raw_msg = false)
        : tag_(std::move(tag)),
          domain_(domain),
          use_raw_msg_(use_raw_msg) {}

protected:
    void sink_it_(const details::log_msg &msg) override {
        const LogLevel level = convert_to_hilog_(msg.level);

        memory_buf_t formatted;
        if (use_raw_msg_) {
            details::fmt_helper::append_string_view(msg.payload, formatted);
        } else {
            base_sink<Mutex>::formatter_->format(msg, formatted);
        }
        formatted.push_back('\0');
        const char *msg_output = formatted.data();

        int ret = OH_LOG_Print(LOG_APP, level, domain_, tag_.c_str(), "%{public}s", msg_output);

        if (ret < 0) {
            throw_spdlog_ex("logging to hilog failed", ret);
        }
    }

    void flush_() override {}

private:
    
    static LogLevel convert_to_hilog_(spdlog::level::level_enum level) {
        switch (level) {
            case spdlog::level::trace:
            case spdlog::level::debug:
                return LOG_DEBUG;
            case spdlog::level::info:
                return LOG_INFO;
            case spdlog::level::warn:
                return LOG_WARN;
            case spdlog::level::err:
                return LOG_ERROR;
            case spdlog::level::critical:
                return LOG_FATAL;
            default:
                return LOG_DEBUG;
        }
    }
    
    std::string tag_;
    bool use_raw_msg_;
    unsigned int domain_;
};

using ohos_hilog_sink_mt = ohos_hilog_sink<std::mutex>;
using ohos_hilog_sink_st = ohos_hilog_sink<details::null_mutex>;

}  // namespace sinks

// Create and register android syslog logger

template <typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> ohos_hilog_logger_mt(const std::string &logger_name,
                                                    const std::string &tag = "spdlog",
                                                    const unsigned int domain = 0x000A) {
    return Factory::template create<sinks::ohos_hilog_sink_mt>(logger_name, tag, domain);
}

template <typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> ohos_hilog_logger_st(const std::string &logger_name,
                                                    const std::string &tag = "spdlog",
                                                    const unsigned int domain = 0x000A) {
    return Factory::template create<sinks::ohos_hilog_sink_st>(logger_name, tag, domain);
}

}  // namespace spdlog

#endif  // __OHOS__
