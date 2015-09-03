#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[])
   {
   if(argc != 2)
      return 1;
   FILE* f = fopen(argv[1], "r");

   if(f == 0)
      return 2;

   char b[10] = { 0 };
   int x = 0, i = 0;

   fread(&b[0], 1, sizeof(b) - 1, f);

   for(i = 0; i != sizeof(b); ++i)
      x += (unsigned int)b[i];

   if(x < 0)
      x = -x;
   printf("%d\n", x);

   printf("%d\n", b[x % 11]);

   if(x > 0 && x % 521 == 0)
      abort();

   return 0;
}
