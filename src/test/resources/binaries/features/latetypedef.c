#include "latetypedef.h"

SpinnerData g_spinnerData;

static void writeHash(StateHash *a)
{
    a->hash = 1;
}

int useLocal(void)
{
    Vec v;
    v.x = 1; v.y = 2;
    return (int)(v.x + v.y);
}

int start(void)
{
    StateHash h;
    writeHash(&h);
    return (int)h.hash + g_spinnerData.spinnerId;
}

int main(void) { return start() + useLocal(); }
