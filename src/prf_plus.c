//
// File:   prf_plus.c
// Author: Fernando Bernal Hidalgo
//

#include "prf_plus.h"

void PRF( u8 * key, u16 key_length, u8 * sequence, u16 sequence_length, u8 * result ) {
    u32 size;
    HMAC((EVP_MD*) EVP_sha1(), key, key_length, sequence, sequence_length, result, &size);
}

void PRF_plus( u8 iter, u8 * key, u16 key_length, u8 * sequence, u16 sequence_length, u8 * result ){    
     u16 prf_size = EVP_MD_size((EVP_MD*) EVP_sha1());
    u8 *temp = malloc(prf_size*sizeof(u8));

    u8 *new_sequence = malloc((prf_size+sequence_length+1)*sizeof(u8)); 

    u8 current_iter = 1;

    // New sequence = S | 0x01
    memcpy(new_sequence, sequence, sequence_length);
    new_sequence[sequence_length] = current_iter;
    
	// Calculate T1 = prf(K, S | 0x01) = prf(K, new_sequence)
    PRF(key, key_length, new_sequence, sequence_length + 1, temp);
    
	// Insert into result
    memcpy(result, temp, prf_size);


    for (current_iter = 2; current_iter <= iter; current_iter++) {
        // New sequence = T | S | iter
        memcpy(new_sequence, temp,prf_size);
        memcpy(&new_sequence[prf_size], sequence, sequence_length);
        new_sequence[prf_size + sequence_length] = current_iter;

        // Calculate T1 = prf(K, S | 0x01) = prf(K, new_sequence)
        PRF(key, key_length, new_sequence, sequence_length + prf_size + 1, temp);
        // Insert into result
        memcpy(&result[ (current_iter - 1) * prf_size], temp, prf_size);
    }

    free(temp);
    free(new_sequence);

}

