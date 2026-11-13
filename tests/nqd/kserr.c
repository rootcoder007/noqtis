/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Measures how far the KS statistic nqddrift gets from the quantile
 * sketch is from the exact two-sample statistic, for normal samples of
 * n and n/2 values, shifted by 0, 0.05 and 0.2, five runs each, with a
 * fixed xorshift generator. Not a ctest: its table is in
 * noqtis-drift(1). Build and run from the source root:
 *   mkdir -p /tmp/kse && cc -O2 -std=c11 -I. -Iinclude tests/nqd/kserr.c \
 *     nqd/*.c build/libnoqtis.a -lm -o kserr && ./kserr
 */
#include "nqd/int.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
static uint64_t s = 88172645463325252u;
static double u(void){ s^=s<<13; s^=s>>7; s^=s<<17; return ((s>>11)+0.5)/9007199254740992.0; }
static double g(void){ return sqrt(-2*log(u()))*cos(6.283185307179586*u()); }
static int cmp(const void*a,const void*b){double x=*(const double*)a,y=*(const double*)b;return x<y?-1:x>y;}
static void wr(const char*p,double*v,size_t n){FILE*f=fopen(p,"w");fprintf(f,"y\n");for(size_t i=0;i<n;i++)fprintf(f,"%.9f\n",v[i]);fclose(f);}
int main(void){
  size_t ns[]={2000,10000,100000,1000000}; double sh[]={0,0.05,0.2};
  for(int a=0;a<4;a++)for(int b=0;b<3;b++){double worst=0,err=0;for(int rep=0;rep<5;rep++){
    size_t n=ns[a],m=n/2; double*x=malloc(n*8),*y=malloc(m*8);
    for(size_t i=0;i<n;i++)x[i]=g(); for(size_t i=0;i<m;i++)y[i]=g()+sh[b];
    wr("/tmp/kse/r.csv",x,n); wr("/tmp/kse/c.csv",y,m);
    /* exact D from the printed values */
    char *o; size_t on; char why[200]; nqdrep*r;
    static char buf[1<<20]; nqdstats("/tmp/kse","r.csv",NULL,buf,sizeof buf,&on,why,sizeof why);
    nqddrift(buf,on,"/tmp/kse/c.csv",NULL,NULL,&r);
    const char*j=nqdrepj(r,1); djs*v; qdjparse(j,strlen(j),&v,why,sizeof why);
    double ds=qdjget(v,"ksd")->d; err=qdjget(v,"kserr")->d;
    for(size_t i=0;i<n;i++){char t[40];snprintf(t,40,"%.9f",x[i]);x[i]=strtod(t,0);} for(size_t i=0;i<m;i++){char t[40];snprintf(t,40,"%.9f",y[i]);y[i]=strtod(t,0);}
    qsort(x,n,8,cmp);qsort(y,m,8,cmp); size_t i=0,k=0; double D=0;
    while(i<n||k<m){double t= k>=m||(i<n&&x[i]<=y[k])?x[i]:y[k]; while(i<n&&x[i]<=t)i++; while(k<m&&y[k]<=t)k++; double dd=fabs((double)i/n-(double)k/m); if(dd>D)D=dd;}
    if(fabs(D-ds)>worst)worst=fabs(D-ds); qdjfree(v); nqdrepfree(r); free(x);free(y);
    (void)o;}
    printf("n %7zu m %7zu shift %.2f: max |D_sketch - D_exact| over 5 runs %.6f, stated bound %.6f\n",ns[a],ns[a]/2,sh[b],worst,err);}
  return 0;}
