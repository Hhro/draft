#include <stdio.h>

int div(int a, int b)
{
    return a / b;
}

int avg(int a, int b)
{
    int k = a + b;
    return div(k, 2);
}

int main()
{
    int a = 3, b = 4;
    for (int i = 0; i < 10; i++)
    {
        printf("%d+%d", i, a);
    }
    printf("average: %d", avg(3, 4));
}