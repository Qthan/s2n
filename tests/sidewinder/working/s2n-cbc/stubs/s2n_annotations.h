#pragma once

#include <smack-contracts.h>
#include "ct-verif.h"

#define S2N_PUBLIC_INPUT( __a )  public_in(__SMACK_value( __a ))
#define S2N_INVARIENT( __a ) invariant ( __a )
