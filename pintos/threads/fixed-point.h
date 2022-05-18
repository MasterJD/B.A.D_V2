#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define p 17
#define q 14
#define f 1 << (q)


#define CONVERT_N_TO_FIXED_POINT(n)  (n)*(f)      
#define CONVERT_X_TO_INT_ZERO(x) (x)/(f)           
#define CONVERT_X_TO_INT_NEAREST(x) ((x) >= 0 ? ((x) + (f) / 2)/ (f) : ((x) - (f) / 2) / (f))             

//operaciones de 2 fixed-point
#define SUM(x,y) (x)+(y)                       
#define RES(x,y) (x)-(y) 
#define MULT(x,y) ((int64_t)(x))*(y)/(f)      
#define DIV(x,y) ((int64_t)(x))*(f)/(y)         

//operaciones fixed point con entero
#define SUMFI(x,n) (x)+ ((n)*(f))             
#define RESFI(x,n) (x)-((n)*(f))
#define MULTFI(x,n) (x)*(n)
#define DIVFI(x,n) (x)/(n)

#endif