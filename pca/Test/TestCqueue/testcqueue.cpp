#include "cqueue.hpp"
#include "common.hpp"
#include <thread>
#include <unistd.h>
#include <stdlib.h>
ConcurrentQueue<string> tq;
int timeis = 0;

void th()
{
    sleep(3);
    tq.Push("haha");
    tq.Push("heheda");
}

// int main()
// {
//     string t;
//     tq.Push("1");
//     tq.Push("2");
//     tq.Pop(t);
//     printf("t is %s \n", t.c_str());
//     tq.Pop(t);
//     printf("t is %s \n", t.c_str());
//     tq.Empty() ? printf("yes its empty\n") : printf("no its not empty");
// }

int main()
{
    string te;
    thread t1(th);
    t1.detach();
    while (true)
    {
        if (timeis || tq.Pop(te))
        {
            printf("te is %s \n", te.c_str());
        }
        timeis++;
        printf("time is %d\n", timeis);
        if (timeis == 20)
        {
            break;
        }
    }
    printf("program over\n");

    return 0;
}
// int main()
// {
//     while (true)
//     {
//         if (!tq.Empty())
//         {
//             string te;
//             tq.Pop(te);
//             printf("te is %s \n", te.c_str());
//         }
//         timeis++;
//         printf("time is %d\n", timeis);
//         if (timeis == 10)
//         {
//             thread t1(th);
//             t1.detach();
//         }
//         if (timeis == 20)
//         {
//             break;
//         }
//     }
//     printf("program over\n");

//     return 0;
// }