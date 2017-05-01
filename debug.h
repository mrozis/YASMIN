#ifndef __DEBUG_H__
#define __DEBUG_H__

//#define DEBUG
#define DEBUG_LEVEL 3

#if !defined(DEBUG) || DEBUG_LEVEL <= 0
#define DEBUG_PRINT_HIGH(...) do {} while(0)
#define DEBUG_PRINT_M(...) do {} while (0)
#define DEBUG_PRINT_LOW(...) do {} while (0)

#elif defined(DEBUG) && DEBUG_LEVEL == 1
#define DEBUG_PRINT_HIGH(...) do { pr_err(__VA_ARGS__);} while (0)
#define DEBUG_PRINT_M(...) do {} while (0)
#define DEBUG_PRINT_LOW(...) do {} while (0)

#elif defined(DEBUG) && DEBUG_LEVEL == 2
#define DEBUG_PRINT_HIGH(...) do { pr_err(__VA_ARGS__);} while (0)
#define DEBUG_PRINT_M(...) do { pr_err(__VA_ARGS__);} while (0)
#define DEBUG_PRINT_LOW(...) do {} while (0)

#elif defined(DEBUG) && DEBUG_LEVEL == 3
#define DEBUG_PRINT_HIGH(...) do { pr_err(__VA_ARGS__);} while (0)
#define DEBUG_PRINT_M(...)		do { pr_err(__VA_ARGS__);} while (0)
#define DEBUG_PRINT_LOW(...)	do { pr_err(__VA_ARGS__);} while (0)

#endif

#endif
