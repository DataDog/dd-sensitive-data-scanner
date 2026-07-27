#ifndef DD_SDS_H
#define DD_SDS_H

/* Generated from the Rust FFI. Run `make update-sds-go-header` to update. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void append_rule_to_list(int64_t rule, int64_t list);

int64_t create_regex_rule(const char *json_config);

int64_t create_rule_list(void);

int64_t create_scanner(int64_t rules,
                       const char *encoded_labels,
                       int32_t enable_debug_observability,
                       const char **error_out);

void delete_scanner(int64_t scanner_id);

void free_any_rule(int64_t rule_ptr);

void free_rule_list(int64_t list);

void free_string(const char *ptr);

void free_vec(const char *ptr, int64_t len, int64_t cap);

const char *scan(int64_t scanner_id,
                 const void *event,
                 int64_t event_size,
                 int64_t *retsize,
                 int64_t *retcapacity,
                 const char **error_out,
                 int32_t with_validate_matching,
                 const char *scan_metadata_json);

const char *validate_regex(const char *regex, const char **error_out);

#endif  /* DD_SDS_H */
