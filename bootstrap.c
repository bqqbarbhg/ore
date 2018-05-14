#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#define buf_len(p) (p ? ((unsigned*)(p))[-1] : 0)
#define buf_cap(p) (p ? ((unsigned*)(p))[-2] : 0)

#define buf_push(p, elem) ((buf_len(p) + 1 >= buf_cap(p) ? (*(void**)&(p) = buf_grow(p, buf_len(p) + 1, sizeof(*(p)))) : (void)0), p[((unsigned*)p)[-1]++] = elem)
#define buf_bump(p) ((buf_len(p) + 1 >= buf_cap(p) ? (*(void**)&(p) = buf_grow(p, buf_len(p) + 1, sizeof(*(p)))) : (void)0), &p[((unsigned*)p)[-1]++])
#define buf_pop(p) (p ? ((unsigned*)p)[-1]-- : (void)0)
#define buf_clear(p) (p ? (((unsigned*)p)[-1] = 0) : (void)0)

#define inl static __forceinline

void *buf_grow(void *p, unsigned num, unsigned elem_sz) {
	unsigned min_cap = 64 / elem_sz;
	unsigned old_cap = buf_cap(p), old_len = buf_len(p);
	unsigned new_cap = old_cap * 2;
	if (num < min_cap) num = min_cap;
	if (new_cap < num) new_cap = num;

	unsigned *oldp = p ? (unsigned*)p - 2 : 0;
	unsigned *newp = (unsigned*)realloc(oldp, new_cap * elem_sz + sizeof(unsigned) * 2);
	newp[0] = new_cap;
	newp[1] = old_len;
	void *retp = newp + 2;
	memset((char*)retp + old_len * elem_sz, 0, (new_cap - old_len) * elem_sz);
	return retp;
}

void buf_free(void *p) {
	if (p != NULL) {
		free((unsigned*)p - 2);
	}
}

typedef struct key_val {
	void *key, *val;
} key_val;

static const unsigned map_caps[] = {
	53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317, 196613,
	393241, 786433, 1572869, 3145739, 6291469, 12582917, 25165843, 50331653, 100663319,
	201326611, 402653189, 805306457, 1610612741,
};

typedef struct map {
	unsigned(*hash_fn)(void *);
	bool(*equal_fn)(void *, void *);

	unsigned *hashes;
	key_val *key_vals;
	unsigned len;
	unsigned cap;
	unsigned cap_ix;
} map;

void map_free(map *m) {
	free(m->hashes);
	free(m->key_vals);
	m->len = 0;
	m->cap = 0;
}

unsigned map__find_impl(map *m, unsigned hash, void *key) {
	if (m->cap == 0) return ~0U;

	unsigned cap = m->cap, pos = hash % cap;
	unsigned *hashes = m->hashes;

	for (;;) {
		if (hashes[pos] == 0) {
			return pos;
		}

		if (hashes[pos] == hash) {
			if (m->equal_fn(m->key_vals[pos].key, key)) {
				return pos;
			}
		}

		pos++;
		if (pos >= cap) pos = 0;
	}

	return ~0U;
}

inl void map__unsafe_set(map *m, unsigned hash, void *key, void *val) {
	unsigned ix = map__find_impl(m, hash, key);
	m->hashes[ix] = hash;
	m->key_vals[ix].key = key;
	m->key_vals[ix].val = val;
	m->len += 1;
}

void map__grow(map *m) {
	map old = *m;

	m->cap = map_caps[m->cap_ix++];

	m->hashes = (unsigned*)malloc(m->cap * sizeof(unsigned));
	m->key_vals = (key_val*)malloc(m->cap * sizeof(key_val));
	m->len = 0;

	memset(m->hashes, 0, m->cap * sizeof(unsigned));

	for (unsigned i = 0; i < old.cap; i++) {
		if (old.hashes[i] != 0) {
			map__unsafe_set(m, old.hashes[i], old.key_vals[i].key, old.key_vals[i].val);
		}
	}

	map_free(&old);
}

inl void map_set(map *m, const void *key, const void *val) {
	if (m->len * 2 >= m->cap) {
		map__grow(m);
	}

	unsigned hash = m->hash_fn((void*)key);
	map__unsafe_set(m, hash, (void*)key, (void*)val);
}

inl void *map_get(map *m, const void *key) {
	unsigned hash = m->hash_fn((void*)key);
	unsigned ix = map__find_impl(m, hash, (void*)key);
	if (ix == ~0U || m->hashes[ix] == 0) return NULL;
	return m->key_vals[ix].val;
}

inl bool map_insert(map *m, const void *key, unsigned *index) {
	if (m->len * 2 >= m->cap) {
		map__grow(m);
	}

	unsigned hash = m->hash_fn((void*)key);
	unsigned ix = map__find_impl(m, hash, (void*)key);
	*index = ix;
	if (m->hashes[ix] == 0) {
		m->len += 1;
		m->hashes[ix] = hash;
		return true;
	}
	else {
		return false;
	}
}

typedef struct file {
	const char *name;
	const char *begin, *pos, *end;
	unsigned length;
	unsigned *linebreaks;
} file;

enum {
	tok_error = 0,
	tok_end = 1000,
	tok_identifier,
	tok_number,
	tok_string,
	tok_eq,
	tok_not_eq,
	tok_le,
	tok_ge,
	tok_or,

	tok_kw_if = 2000,
	tok_kw_else,
	tok_kw_def,
	tok_kw_val,
	tok_kw_var,
	tok_kw_inline,
	tok_kw_unsafe,
	tok_kw_trait,
	tok_kw_namespace,
	tok_kw_extern,
	tok_kw_type,
	tok_kw_struct,
	tok_kw_class,
	tok_kw_new,
	tok_kw_impl,
	tok_kw_extends,
};

typedef struct token {
	unsigned file, begin, end, kind;
	const char *str;
} token;

typedef enum ast_kind {
	ast_invalid,
	ast_identifier,
	ast_number,
	ast_decl,
	ast_func,
	ast_binop,
	ast_call,
	ast_toplevel,
} ast_kind;

typedef struct ast {
	ast_kind kind;
	unsigned serial;

	union {
		struct {
			token name;
		} identifier;

		struct {
			token value;
		} number;

		struct {
			token op;
			struct ast *left, *right;
		} binop;

		struct {
			token paren;
			struct ast *func;
			struct ast **args;
		} call;

		struct {
			token name;
			struct ast *type;
		} decl;

		struct {
			token name;
			struct ast **arg_decls;
			struct ast *ret_type;
			struct ast *body;
		} func;

		struct {
			struct ast **statements;
		} toplevel;
	};
} ast;

typedef struct compiler_state {
	map strings;
	map types;

	file *files;
	file *file;
	char *error;
	token token;

	char *alloc;
	size_t alloc_pos;
	size_t alloc_cap;

	unsigned ast_serial;

	map keywords;
} compiler_state;

inl char peek(compiler_state *s) { file *f = s->file; return f->pos != f->end ? *f->pos : '\0'; }
inl char eat(compiler_state *s) { file *f = s->file; if (f->pos < f->end) f->pos++; return peek(s); }

inl bool range(char c, char range[2]) { return c >= range[0] && c <= range[1]; }
inl bool whitespace(char c) { return c == ' ' || c == '\t' || c == '\r'; }
inl bool id_head(char c) { return range(c, "AZ") || range(c, "az") || c == '_'; }
inl bool id_tail(char c) { return id_head(c) || range(c, "09"); }
inl bool digit(char c) { return range(c, "09"); }

#define array_len(arr) (sizeof(arr) / sizeof(*(arr)))

void find_line_col(file *f, unsigned pos, unsigned *line, unsigned *col) {
	unsigned count = buf_len(f->linebreaks), first = 0, step, it;
	while (count > 0) {
		step = count >> 1;
		it = first + step;
		if (f->linebreaks[it] < pos) {
			first = it + 1;
			count -= step + 1;
		}
		else {
			count = step;
		}
	}

	*line = first;
	if (first == 0) {
		*col = pos;
	}
	else if (first < buf_len(f->linebreaks)) {
		*col = pos - f->linebreaks[first];
	}
	else {
		*col = 0;
	}
}

void error_global(compiler_state *s, const char *fmt, ...) {
	char *res = (char*)malloc(4096);
	va_list args;
	va_start(args, fmt);
	vsprintf(res, fmt, args);
	va_end(args);
	s->error = res;
}

void error_at(compiler_state *s, token tok, const char *fmt, ...) {
	char msg[1024], *res = (char*)malloc(4096);
	file *file = &s->files[tok.file];
	unsigned line, col;
	find_line_col(file, tok.begin, &line, &col);

	va_list args;
	va_start(args, fmt);
	vsprintf(msg, fmt, args);
	va_end(args);

	sprintf(res, "%s:%d:%d: %s", file->name, line + 1, col + 1, msg);
	s->error = res;
}

void push_file(compiler_state *s, const char *filename) {
	FILE *fl = fopen(filename, "rb");
	if (fl == NULL) {
		error_global(s, "Could not open file '%s'", filename);
		return;
	}

	file *f = buf_bump(s->files);
	s->file = f;
	f->name = strdup(filename);

	fseek(fl, 0, SEEK_END);
	size_t size = ftell(fl);
	fseek(fl, 0, SEEK_SET);

	char *data = (char*)malloc(size + 1);
	fread(data, 1, size, fl);
	data[size] = '\0';
	fclose(fl);

	f->begin = f->pos = data;
	f->end = data + size;
	f->length = (unsigned)size;
}

typedef struct string_span {
	const char *data;
	size_t length;
} string_span;

bool string_span_equal(void *va, void *vb) {
	string_span *a = (string_span*)va, *b = (string_span*)vb;
	return a->length == b->length && !memcmp(a->data, b->data, a->length);
}

unsigned string_span_hash(void *va) {
	string_span *a = (string_span*)va;
	const char *begin = a->data, *end = begin + a->length;
	unsigned hash = 16777619U;
	for (; begin != end; ++begin) {
		hash = (hash ^ *begin) * 2166136261U;
	}
	return hash;
}

bool identifier_equal(void *va, void *vb) {
	return va == vb;
}

unsigned identifier_hash(void *va) {
	return (unsigned)(uintptr_t)va >> 3;
}

const char *intern_str(compiler_state *s, const char *str, size_t length) {
	string_span span;
	span.data = str;
	span.length = length;
	unsigned ix;
	if (map_insert(&s->strings, &span, &ix)) {
		string_span *key = (string_span*)malloc(sizeof(string_span) + span.length + 1);
		key->data = (char*)(key + 1);
		key->length = span.length;
		memcpy(key + 1, span.data, span.length);
		((char*)(key + 1))[span.length] = '\0';
		s->strings.key_vals[ix].key = key;
	}

	return ((string_span*)s->strings.key_vals[ix].key)->data;
}

inl const char *intern_str_zero(compiler_state *s, const char *str) {
	return intern_str(s, str, strlen(str));
}

void lex(compiler_state *s) {
	if (s->error) return;

	char c = peek(s);

	while (whitespace(c)) {
		c = eat(s);
	}

	s->token.file = (unsigned)(s->file - s->files);
	s->token.begin = (unsigned)(s->file->pos - s->file->begin);
	s->token.kind = tok_error;
	s->token.end = s->token.begin + 1;

	if (id_head(c)) {
		const char *begin = s->file->pos;

		do {
			c = eat(s);
		} while (id_tail(c));
		s->token.kind = tok_identifier;

		const char *end = s->file->pos;
		size_t len = end - begin;

		goto accept;
	}

	if (digit(c)) {
		do {
			c = eat(s);
		} while (digit(c));
		s->token.kind = tok_number;
		goto accept;
	}

	if (c == '"') {
		do {
			c = eat(s);
			if (c == '\\') c = eat(s);
			if (c == '\0') {
				error_at(s, s->token, "Unclosed string literal");
				return;
			}
		} while (c != '"');
		eat(s);
		s->token.kind = tok_string;
		goto accept;
	}

	char la = eat(s);
	switch (c) {

	case '\0':
		s->token.kind = tok_end;
		goto accept;

	case '+': case '-': case '*': case '/': case '.':
	case '(': case ')': case ':': case ',': case '{': case '}': case '[': case ']':
		s->token.kind = c;
		goto accept;

	case '=':
		s->token.kind = la == '=' ? eat(s), tok_eq : '=';
		goto accept;

	case '!':
		s->token.kind = la == '=' ? eat(s), tok_not_eq : '!';
		goto accept;

	case '<':
		s->token.kind = la == '=' ? eat(s), tok_le : '<';
		goto accept;

	case '>':
		s->token.kind = la == '=' ? eat(s), tok_ge : '>';
		goto accept;

	case '|':
		s->token.kind = la == '|' ? eat(s), tok_or : '|';
		goto accept;

	case '\n':
		buf_push(s->file->linebreaks, (unsigned)(s->file->pos - s->file->begin));
		s->token.kind = '\n';
		goto accept;

	default:
		if (c >= 33 && c <= 128)
			error_at(s, s->token, "Unexpected character: '%c'", c);
		else
			error_at(s, s->token, "Unexpected character: '0x%02x'", c);
		return;
	}

accept:
	s->token.end = (unsigned)(s->file->pos - s->file->begin);
	s->token.str = intern_str(s, s->file->begin + s->token.begin, s->token.end - s->token.begin);

	if (s->token.kind == tok_identifier) {
		uintptr_t kw = (uintptr_t)map_get(&s->keywords, s->token.str);
		if (kw != 0) {
			s->token.kind = (unsigned)kw;
		}
	}
}

void add_keyword(compiler_state *s, const char *name, unsigned kind) {
	const char *interned = intern_str_zero(s, name);
	map_set(&s->keywords, interned, (void*)(uintptr_t)kind);
}

void init_compiler(compiler_state *s) {
	memset(s, 0, sizeof(*s));
	s->strings.hash_fn = string_span_hash;
	s->strings.equal_fn = string_span_equal;
	s->keywords.hash_fn = identifier_hash;
	s->keywords.equal_fn = identifier_equal;

	add_keyword(s, "if", tok_kw_if);
	add_keyword(s, "else", tok_kw_else);
	add_keyword(s, "def", tok_kw_def);
	add_keyword(s, "val", tok_kw_val);
	add_keyword(s, "var", tok_kw_var);
	add_keyword(s, "inline", tok_kw_inline);
	add_keyword(s, "unsafe", tok_kw_unsafe);
	add_keyword(s, "trait", tok_kw_trait);
	add_keyword(s, "namespace", tok_kw_namespace);
	add_keyword(s, "extern", tok_kw_extern);
	add_keyword(s, "type", tok_kw_type);
	add_keyword(s, "trait", tok_kw_trait);
	add_keyword(s, "struct", tok_kw_struct);
	add_keyword(s, "class", tok_kw_class);
	add_keyword(s, "new", tok_kw_new);
	add_keyword(s, "impl", tok_kw_impl);
	add_keyword(s, "extends", tok_kw_extends);
}

int main(int argc, char **argv) {
	compiler_state cs, *s = &cs;

	init_compiler(s);
	push_file(s, argv[1]);

	do {
		lex(s);
		printf("%s: %d\n", s->token.str, s->token.kind);
	} while (!s->error && s->token.kind != tok_end);

	if (s->error) {
		printf("Error: %s\n", s->error);
	}

	getchar();
	return 0;
}
