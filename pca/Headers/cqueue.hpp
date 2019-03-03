#ifndef NET_FRAME_CONCURRENT_QUEUE_H
#define NET_FRAME_CONCURRENT_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

template <class Type>
class ConcurrentQueue
{
    ConcurrentQueue &operator=(const ConcurrentQueue &) = delete;

    ConcurrentQueue(const ConcurrentQueue &other) = delete;

  public:
    ConcurrentQueue() : _queue(), _mutex(), _condition() {}

    virtual ~ConcurrentQueue() {}

    void Push(Type record)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _queue.push(record);
        _condition.notify_one();
    }

    bool Pop(Type &record, bool isBlocked = true)
    {
        if (isBlocked)
        {
            std::unique_lock<std::mutex> lock(_mutex);
            while (_queue.empty())
            {
                _condition.wait(lock);
            }
        }
        else // If user wants to retrieve data in non-blocking mode
        {
            std::lock_guard<std::mutex> lock(_mutex);
            if (_queue.empty())
            {
                return false;
            }
        }

        record = std::move(_queue.front());
        _queue.pop();
        return true;
    }

    int32_t Size()
    {
        std::lock_guard<std::mutex> lock(_mutex);
        return _queue.size();
    }

    bool Empty()
    {
        std::lock_guard<std::mutex> lock(_mutex);
        return _queue.empty();
    }

  private:
    std::queue<Type> _queue;
    mutable std::mutex _mutex;
    std::condition_variable _condition;
};

#endif //NET_FRAME_CONCURRENT_QUEUE_H
