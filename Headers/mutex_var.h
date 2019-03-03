#ifndef MUTEX_VAR_H
#define MUTEX_VAR_H

#include <queue>
#include <mutex>
#include <condition_variable>

namespace mutex_var {
//mutex makes global var read/write safe.  

    template <class Type>
    class ConcurrentQueue {
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


    class Stage {
    public:
        Stage() : _stage(0), _mutex() {}

        virtual ~Stage() {}

        void Set(int value)
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _stage = value;
        }

        void Calc_Or(int value) {
            std::lock_guard<std::mutex> lock(_mutex);
            _stage = _stage | value;
        }

        void Calc_And(int value) {
            std::lock_guard<std::mutex> lock(_mutex);
            _stage = _stage & value;            
        }

        int Get()
        {
            //std::lock_guard<std::mutex> lock(_mutex);
            return _stage;
        }

    private:
        int _stage;
        mutable std::mutex _mutex;
    };

}
#endif //MUTEX_VAR_H
