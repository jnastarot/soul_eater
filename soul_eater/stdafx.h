#pragma once

#define WIN32_LEAN_AND_MEAN

#include <algorithm>
#include <cstdint>
#include <vector>
#include <list>
#include <math.h>
#include <map>
#include <set>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <stdarg.h> 
#include <iostream>
#include <iostream>

#include <locale.h>

using namespace std;


#pragma comment(lib, "capstone.lib")
#pragma comment(lib, "enma_pe.lib")
#pragma comment(lib, "fukutasm.lib")

#include "enma_pe\enma_pe\enma_pe.h"
#include "capstone\include\capstone\capstone.h"
#include "fukutasm\fukutasm\fukutasm.h"