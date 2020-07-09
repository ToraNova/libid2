#include "id2.hpp"
#include <sodium.h>
#include "utils/debug.h"

namespace id2{

	//initialize libsodium secure memory
	//return 0 on success, 1 on fail
	int initialize(){
		if(sodium_init() == 0){
			return 0;
		}else {
			lerror("Unable to initialize libsodium secure memory!\n");
			return 1;
		}
	}

}
