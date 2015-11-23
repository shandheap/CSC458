
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = malloc(sizeof(struct sr_nat_mapping));

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping * cur, next;
  struct sr_nat_connection * cur_conn, next_conn;

  /* free nat memory here */
  cur = nat->mappings;
  while (cur) {
    /* Save pointer to next mapping */
    next = cur->next;

    cur_conn = cur->conns;
    /* Free nat connections */
    while (cur_conn) {
      next_conn = cur_conn->next;

      free(cur_conn);
      cur_conn = next_conn;
    }

    /* Free nat memory */
    free(cur);
    cur = next;
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr)) &&
    pthread_attr_destroy(&(nat->thread_attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    /* TODO: Change max interval */
    struct sr_nat_mapping * cur, next;

    /* free nat memory here */
    cur = nat->mappings;
    while (cur) {
      next = cur->next;
      cur_conn = cur->conns;
      /* Check if nat entry has timed out */
      if (difftime(curtime, cur->last_updated) > 60) {
        /* Free nat connections */
        while (cur_conn) {
          next_conn = cur_conn->next;

          free(cur_conn);
          cur_conn = next_conn;
        }

        /* Free nat memory */
        free(cur);
      }

      cur = next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  /* Do nat lookup */
  struct sr_nat_mapping * cur, next;
  cur = nat->mappings;
  while (cur) {
    next = cur->next;
    if (cur->aux_ext == aux_ext && cur->type == type) {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, cur, sizeof(struct sr_nat_mapping));
    }
    cur = next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  /* Do nat lookup */
  struct sr_nat_mapping * cur, next;
  cur = nat->mappings;
  while (cur) {
    next = cur->next;
    if (cur->ip_int == ip_int && cur->aux_int == aux_int && cur->type == type) {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, cur, sizeof(struct sr_nat_mapping));
    }
    cur = next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  /* Construct nat mapping */
  mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  time(&(mapping->last_updated));
  mapping->conns = NULL;
  mapping->next = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
