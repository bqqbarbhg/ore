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
	tok_and,

	tok_op_assign = 2000,
	tok_add_assign = tok_op_assign + '+',
	tok_sub_assign = tok_op_assign + '-',
	tok_mul_assign = tok_op_assign + '*',
	tok_div_assign = tok_op_assign + '/',

	tok_kw_if = 3000,
	tok_kw_else,
	tok_kw_while,
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

	ast_namespace,
	ast_extern,
	ast_block,
	ast_identifier,
	ast_number,
	ast_generic,
	ast_decl,
	ast_ref,

	ast_def,
	ast_if,
	ast_while,
	ast_type,
	ast_typedecl,
	ast_vardecl,
	ast_assign,

	ast_member,
	ast_call,
	ast_unop,
	ast_binop,
	ast_paren,
	ast_new,
	ast_sizeof,

} ast_kind;

enum {
	mod_unsafe = 1 << 0,
	mod_inline = 1 << 1,
};

typedef struct ast ast;

struct ast {
	ast_kind kind;
	unsigned serial;
	token token;

	union {

		struct {
			token name;
			ast *stmt;
		} namespace_;

		struct {
			token format;
			ast *stmt;
		} extern_;

		struct {
			ast **stmts;
		} block;

		struct {
			token name;
		} identifier;

		struct {
			token value;
		} number;

		struct {
			ast *name;
			ast **args;
		} generic;

		struct {
			token name;
			ast *type;
		} decl;

		struct {
			ast *decl;
		} ref;

		struct {
			ast *name;
			ast **args;
			ast *ret;
			ast *body;
			unsigned mods;
			bool no_parens;
		} def;

		struct {
			ast **conds;
			ast **bodies;
			ast *else_body;
		} if_;

		struct {
			ast *cond;
			ast *body;
		} while_;

		struct {
			token kind;
			ast *name;
			ast **extends;
			ast **stmts;
			unsigned mods;
		} type;

		struct {
			token kind;
			ast *name;
			ast *init;
			unsigned mods;
		} typedecl;

		struct {
			token kind;
			token name;
			ast *type;
			ast *init;
			unsigned mods;
		} vardecl;

		struct {
			token op;
			ast *left, *right;
		} assign;

		struct {
			ast *left;
			token name;
		} member;

		struct {
			ast *left;
			ast **args;
		} call;

		struct {
			token op;
			ast *arg;
		} unop;

		struct {
			token op;
			ast *left, *right;
		} binop;

		struct {
			ast *expr;
		} paren;

		struct {
			ast *type;
			ast **args;
		} new_;

		struct {
			ast *type;
		} sizeof_;

	};
};

typedef struct compiler_state {
	map strings;
	map types;

	file *files;
	file *file;
	char *error;
	char *errorline[2];
	token prev_token;
	token token;
	token unlex_token;
	bool unlex_state;

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

void grow_allocator(compiler_state *s, size_t size) {
	s->alloc_cap *= 2;
	if (s->alloc_cap < 1024) s->alloc_cap = 1024;
	if (s->alloc_cap < size) s->alloc_cap = size;
	s->alloc = (char*)calloc(s->alloc_cap, 1);
	s->alloc_pos = 0;
}

#define push_mem(s, type) (type*)push_memory((s), sizeof(type))

inl void *push_memory(compiler_state *s, size_t size) {
	size += ((8 - (size & 7)) & 7);
	if (s->alloc_pos + size > s->alloc_cap) {
		grow_allocator(s, size);
	}
	size_t pos = s->alloc_pos;
	s->alloc_pos = pos + size;
	return s->alloc + pos;
}

inl ast *push_ast(compiler_state *s, ast_kind kind) {
	ast *a = push_mem(s, ast);
	a->kind = kind;
	a->serial = ++s->ast_serial;
	a->token = s->prev_token;
	return a;
}

void find_line_col(file *f, unsigned pos, unsigned *line, unsigned *col) {
	unsigned count = buf_len(f->linebreaks), first = 0, step, it;
	while (count > 0) {
		step = count >> 1;
		it = first + step;
		if (f->linebreaks[it] < pos) {
			first = it + 1;
			count -= step + 1;
		} else {
			count = step;
		}
	}

	*line = first;
	if (first == 0) {
		*col = pos;
	} else if (first < buf_len(f->linebreaks)) {
		*col = pos - f->linebreaks[first];
	} else if (buf_len(f->linebreaks) > 0) {
		*col = pos - f->linebreaks[buf_len(f->linebreaks) - 1];
	} else {
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
	if (s->error) return;

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

	s->errorline[0] = (char*)malloc(4096);
	s->errorline[1] = (char*)malloc(4096);

	const char *ee = file->begin + tok.begin, *eb = ee;
	while (eb >= file->begin + 1 && eb[-1] != '\t' && eb[-1] != '\n' && eb[-1] != '\r') {
		eb--;
	}
	while (ee < file->end && *ee != '\n' && *ee != '\r') {
		ee++;
	}

	memcpy(s->errorline[0], eb, ee - eb);
	s->errorline[0][ee - eb] = '\0';

	const char *tb = file->begin + tok.begin, *te = file->begin + tok.end;
	char *out = s->errorline[1];
	for (const char *ec = eb; ec < ee; ec++) {
		char c;
		if (ec < tb || ec >= te) {
			c = ' ';
		} else if (ec == tb || ec == te - 1) {
			c = '^';
		} else {
			c = '~';
		}
		*out++ = c;
	}
	*out++ = '\0';
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

	s->prev_token = s->token;
	if (s->unlex_state) {
		s->token = s->unlex_token;
		s->unlex_state = false;
		return;
	}

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

	case '+': case '-': case '*': case '/':
		s->token.kind = la == '=' ? eat(s), tok_op_assign + c : c;
		goto accept;

	case '.': case '(': case ')': case ':': case ',': case '{': case '}': case '[': case ']':
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

	case '&':
		s->token.kind = la == '&' ? eat(s), tok_and : '&';
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

void unlex(compiler_state *s) {
	s->unlex_token = s->token;
	s->token = s->prev_token;
	s->unlex_state = true;
}

inl bool accept(compiler_state *s, unsigned kind) {
	if (s->error) return false;

	if (s->token.kind == kind) {
		lex(s);
		return true;
	}
	else {
		return false;
	}
}

inl bool require(compiler_state *s, unsigned kind, const char *context) {
	if (s->error) return false;

	if (!accept(s, kind)) {
		error_at(s, s->token, "%s", context);
		return false;
	}

	return true;
}

unsigned token_to_mod(unsigned kind) {
	switch (kind) {
	case tok_kw_inline: return mod_inline;
	case tok_kw_unsafe: return mod_unsafe;
	default:
		assert(0 && "Unexpected modifier kind");
		return 0;
	}
}

ast *parse_name(compiler_state *s) {
	if (!require(s, tok_identifier, "Expected a name")) return NULL;
	ast *id = push_ast(s, ast_identifier);
	id->identifier.name = s->prev_token;

	if (accept(s, '[')) {
		ast *gen = push_ast(s, ast_generic);
		gen->generic.name = id;

		if (s->token.kind == ']') {
			error_at(s, s->token, "Generic parameter list cannot be empty");
			return NULL;
		}

		do {
			require(s, tok_identifier, "Expected a generic argument name");
			ast *arg = push_ast(s, ast_identifier);
			arg->identifier.name = s->prev_token;
			buf_push(gen->generic.args, arg);
		} while (accept(s, ','));

		require(s, ']', "Expected closing ']' after generic argument list");
		return gen;
	} else {
		return id;
	}
}

ast *parse_statement(compiler_state *s);
ast *parse_expr(compiler_state *s);
ast *parse_type(compiler_state *s);

ast *parse_expr_atom(compiler_state *s) {
	ast *a = NULL;

	lex(s);
	switch (s->prev_token.kind) {

	case tok_identifier:
		a = push_ast(s, ast_identifier);
		a->identifier.name = s->prev_token;
		break;

	case tok_number:
		a = push_ast(s, ast_number);
		a->number.value = s->prev_token;
		break;

	case '(':
		a = push_ast(s, ast_paren);
		a->paren.expr = parse_expr(s);
		require(s, ')', "Expected a closing ')'");
		break;

	case '{':
		a = push_ast(s, ast_block);
		while (accept(s, '\n')) { }
		while (!accept(s, '}') && !s->error) {
			ast *st = parse_statement(s);
			if (st != NULL) {
				buf_push(a->block.stmts, st);
			} else if (!s->error) {
				error_at(s, s->prev_token, "Expected a statement");
			}
			while (accept(s, '\n')) { }
		}
		break;

	default:
		error_at(s, s->prev_token, "Expected an expression");
		return NULL;
	}

	return s->error ? NULL : a;
}

ast *parse_expr_suffix(compiler_state *s) {
	ast *a = parse_expr_atom(s);

	while (!s->error) {
		lex(s);
		switch (s->prev_token.kind) {

		case '.': {
			ast *op = push_ast(s, ast_member);
			op->member.left = a;
			require(s, tok_identifier, "Expected a member name after '.'");
			op->member.name = s->prev_token;
			a = op;
		} break;

		case '[': {
			ast *op = push_ast(s, ast_generic);
			op->generic.name = a;

			if (s->token.kind == ']') {
				error_at(s, s->token, "Generic parameter list cannot be empty");
				return NULL;
			}

			do {
				ast *arg = parse_type(s);
				buf_push(op->generic.args, arg);
			} while (accept(s, ','));

			require(s, ']', "Expected closing ']' for generic parameter list");
				
			a = op;
		} break;

		case '(': {
			ast *op = push_ast(s, ast_call);
			op->call.left = a;

			if (!accept(s, ')')) {
				do {
					ast *arg = parse_expr(s);
					buf_push(op->call.args, arg);
				} while (accept(s, ','));

				require(s, ')', "Expected closing ')' for function call");
			}

			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_expr_prefix(compiler_state *s) {
	ast *a = NULL;

	lex(s);
	switch (s->prev_token.kind) {
	case '!':
		a = push_ast(s, ast_unop);
		a->unop.op = s->prev_token;
		a->unop.arg = parse_expr_suffix(s);
		break;

	default:
		unlex(s);
		a = parse_expr_suffix(s);
	}

	return s->error ? NULL : a;
}

ast *parse_expr_1_mul(compiler_state *s) {
	ast *a = parse_expr_prefix(s);

	while (!s->error) {
		lex(s);
		switch (s->prev_token.kind) {

		case '*': case '/': case '%': {
			ast *op = push_ast(s, ast_binop);
			op->binop.op = s->prev_token;
			op->binop.left = a;
			op->binop.right = parse_expr_prefix(s);
			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_expr_2_add(compiler_state *s) {
	ast *a = parse_expr_1_mul(s);

	while (!s->error) {
		lex(s);
		switch (s->prev_token.kind) {

		case '+': case '-': {
			ast *op = push_ast(s, ast_binop);
			op->binop.op = s->prev_token;
			op->binop.left = a;
			op->binop.right = parse_expr_1_mul(s);
			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_expr_3_cmp(compiler_state *s) {
	ast *a = parse_expr_2_add(s);

	while (!s->error) {
		lex(s);
		switch (s->prev_token.kind) {

		case tok_eq: case tok_not_eq: case tok_ge: case tok_le:
		case '<': case '>': {
			ast *op = push_ast(s, ast_binop);
			op->binop.op = s->prev_token;
			op->binop.left = a;
			op->binop.right = parse_expr_2_add(s);
			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_expr_4_and(compiler_state *s) {
	ast *a = parse_expr_3_cmp(s);

	while (!s->error) {
		lex(s);
		switch (s->prev_token.kind) {
		case tok_and: {
			ast *op = push_ast(s, ast_binop);
			op->binop.op = s->prev_token;
			op->binop.left = a;
			op->binop.right = parse_expr_3_cmp(s);
			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_expr_5_or(compiler_state *s) {
	ast *a = parse_expr_4_and(s);

	while (!s->error) {

		lex(s);
		switch (s->prev_token.kind) {
		case tok_or: {
			ast *op = push_ast(s, ast_binop);
			op->binop.op = s->prev_token;
			op->binop.left = a;
			op->binop.right = parse_expr_4_and(s);
			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_expr(compiler_state *s) {

	ast *a = NULL;

	lex(s);
	switch (s->prev_token.kind) {
	
	case tok_kw_if: {
		ast *cond, *body;
		a = push_ast(s, ast_if);
		require(s, '(', "Expected '(' for if condition");
		cond = parse_expr(s);
		buf_push(a->if_.conds, cond);
		require(s, ')', "Expected closing ')' for if condition");
		while (accept(s, '\n')) { }
		body = parse_statement(s);
		buf_push(a->if_.bodies, body);

another_elseif:
		if (accept(s, tok_kw_else)) {
			while (accept(s, '\n')) { }
			if (accept(s, tok_kw_if)) {
				require(s, '(', "Expected '(' for else if condition");
				cond = parse_expr(s);
				buf_push(a->if_.conds, cond);
				require(s, ')', "Expected closing ')' for else if condition");
				while (accept(s, '\n')) { }
				body = parse_statement(s);
				buf_push(a->if_.bodies, body);
				goto another_elseif;
			} else {
				a->if_.else_body = parse_statement(s);
			}
		}
	} break;

	case tok_kw_while: {
		a = push_ast(s, ast_while);
		require(s, '(', "Expected '(' for while condition");
		a->while_.cond = parse_expr(s);
		require(s, ')', "Expected closing ')' for while condition");
		a->while_.body = parse_statement(s);
	} break;

	case tok_kw_new: {
		a = push_ast(s, ast_new);

		if (s->token.kind != '{') {
			a->new_.type = parse_type(s);
		}

		if (accept(s, '{')) {
			if (s->token.kind != '}') {
				do {
					ast *arg = parse_expr(s);

					if (accept(s, '=')) {
						ast *name = arg;
						arg = push_ast(s, ast_assign);
						arg->assign.op = s->prev_token;
						arg->assign.left = name;
						arg->assign.right = parse_expr(s);
					}

					buf_push(a->new_.args, arg);
				} while (accept(s, ','));
			}

			require(s, '}', "Expected closing '}' for initailizer block");
		} else {
			// TODO: Constructors
		}

	} break;

	default:
		unlex(s);
		a = parse_expr_5_or(s);
	}

	return s->error ? NULL : a;
}

ast *finish_type_name(compiler_state *s, token name) {
	ast *a = push_ast(s, ast_identifier);
	a->identifier.name = s->prev_token;

	while (!s->error) {
		lex(s);
		switch (s->prev_token.kind) {

		case '.': {
			ast *op = push_ast(s, ast_member);
			op->member.left = a;
			require(s, tok_identifier, "Expected a member name after '.'");
			op->member.name = s->prev_token;
			a = op;
		} break;

		case '[': {
			ast *op = push_ast(s, ast_generic);
			op->generic.name = a;

			if (s->token.kind == ']') {
				error_at(s, s->token, "Generic parameter list cannot be empty");
				return NULL;
			}

			do {
				ast *arg = parse_type(s);
				buf_push(op->generic.args, arg);
			} while (accept(s, ','));

			require(s, ']', "Expected closing ']' for generic parameter list");
				
			a = op;
		} break;

		default:
			unlex(s);
			return a;
		}
	}

	return s->error ? NULL : a;
}

ast *parse_type(compiler_state *s) {
	ast *a = NULL;

	lex(s);
	switch (s->prev_token.kind) {

	case '*':
		a = push_ast(s, ast_ref);
		a->ref.decl = parse_type(s);
		break;

	case tok_identifier:
		a = finish_type_name(s, s->prev_token);
		break;

	default:
		error_at(s, s->prev_token, "Expected a type");
		break;
	}

	return s->error ? NULL : a;
}

ast *parse_free_statement(compiler_state *s) {
	if (s->error) return NULL;
	ast *a = NULL;

	lex(s);
	token tok = s->prev_token;
	switch (tok.kind) {

	case tok_kw_inline:
	case tok_kw_unsafe: {
		unsigned mod = token_to_mod(tok.kind);
		a = parse_free_statement(s);
		if (a == NULL) return NULL;

		switch (a->kind) {

		case ast_type:
			switch (tok.kind) {
			case tok_kw_unsafe:
				a->type.mods |= mod;
				break;
			default:
				error_at(s, tok, "Cannot mark type as '%s'", tok.str);
			}
			break;

		case ast_typedecl:
			switch (tok.kind) {
			case tok_kw_unsafe:
				a->typedecl.mods |= mod;
				break;
			default: error_at(s, tok, "Cannot mark type as '%s'", tok.str);
			}
			break;

		case ast_vardecl:
			switch (tok.kind) {
			case tok_kw_unsafe:
				a->typedecl.mods |= mod;
				break;
			default: error_at(s, tok, "Cannot mark variable as '%s'", tok.str);
			}
			break;

		case ast_def:
			switch (tok.kind) {
			case tok_kw_inline:
			case tok_kw_unsafe:
				a->def.mods |= mod;
				break;
			default: error_at(s, tok, "Cannot mark function definition as '%s'", tok.str);
			}
			break;

		default:
			error_at(s, tok, "Cannot mark non-declaration as '%s'", tok.str);
			return NULL;
		}

	} break;

	case tok_kw_impl:
	case tok_kw_trait:
	case tok_kw_struct:
	case tok_kw_class:
		a = push_ast(s, ast_type);
		a->type.kind = s->prev_token;
		a->type.name = parse_name(s);

		if (accept(s, tok_kw_extends)) {
			do {
				ast *b = parse_type(s);
				buf_push(a->type.extends, b);
			} while (accept(s, ','));
		}

		if (!require(s, '{', "Expected type declaration block '{'")) return NULL;
		while (accept(s, '\n')) { }
		while (!accept(s, '}') && !s->error) {
			ast *b = parse_free_statement(s);
			buf_push(a->type.stmts, b);
			while (accept(s, '\n')) { }
		}
		break;

	case tok_kw_var:
	case tok_kw_val:
		a = push_ast(s, ast_vardecl);
		a->vardecl.kind = s->prev_token;
		require(s, tok_identifier, "Variable declaration name");
		a->vardecl.name = s->prev_token;
		if (accept(s, ':')) {
			a->vardecl.type = parse_type(s);
		}
		if (accept(s, '=')) {
			a->vardecl.init = parse_expr(s);
		}
		break;

	case tok_kw_type:
		a = push_ast(s, ast_typedecl);
		a->typedecl.name = parse_name(s);
		a->typedecl.kind = s->prev_token;
		if (accept(s, '=')) {
			a->typedecl.init = parse_type(s);
		}
		break;

	case tok_kw_def:
		a = push_ast(s, ast_def);
		a->def.name = parse_name(s);

		if (accept(s, '(')) {
			if (!accept(s, ')')) {
				do {
					ast *decl = push_ast(s, ast_decl);
					require(s, tok_identifier, "Expected argument name");
					decl->decl.name = s->prev_token;
					if (!require(s, ':', "Expected parameter type")) return NULL;
					decl->decl.type = parse_type(s);
					buf_push(a->def.args, decl);
				} while (accept(s, ','));

				require(s, ')', "Expected closing ')'");
			}
		} else {
			a->def.no_parens = true;
		}

		if (accept(s, ':')) {
			a->def.ret = parse_type(s);
		}

		if (accept(s, '=')) {
			a->def.body = parse_expr(s);
		} else if (s->token.kind == '{') {
			a->def.body = parse_expr(s);
		}

		break;

	case '{':
		a = push_ast(s, ast_block);
		while (accept(s, '\n')) { }
		while (!accept(s, '}') && !s->error) {
			ast *st = parse_free_statement(s);
			if (st != NULL) {
				buf_push(a->block.stmts, st);
			} else if (!s->error) {
				error_at(s, s->prev_token, "Expected a free statement");
			}
			while (accept(s, '\n')) { }
		}
		break;

	default:
		unlex(s);
		return NULL;

	}

	return s->error ? NULL : a;
}

ast *parse_statement(compiler_state *s) {
	if (s->error) return NULL;
	ast *a = NULL;

	lex(s);
	switch (s->prev_token.kind) {

	case '{':
		a = push_ast(s, ast_block);
		while (accept(s, '\n')) { }
		while (!accept(s, '}') && !s->error) {
			ast *st = parse_statement(s);
			if (st != NULL) {
				buf_push(a->block.stmts, st);
			} else if (!s->error) {
				error_at(s, s->prev_token, "Expected a statement");
			}
			while (accept(s, '\n')) { }
		}
		break;

	default:
		unlex(s);
		a = parse_free_statement(s);
		if (a == NULL && !s->error) {
			a = parse_expr(s);

			lex(s);
			switch (s->prev_token.kind) {
			case '=':
			case tok_add_assign: case tok_sub_assign:
			case tok_mul_assign: case tok_div_assign: {
				ast *left = a;
				a = push_ast(s, ast_assign);
				a->assign.op = s->prev_token;
				a->assign.left = left;
				a->assign.right = parse_expr(s);
			} break;

			default:
				unlex(s);
			}
		}

	}

	return s->error ? NULL : a;
}

ast *parse_toplevel(compiler_state *s) {
	if (s->error) return NULL;
	ast *a = NULL;

	lex(s);
	switch (s->prev_token.kind) {

	case tok_kw_namespace:
		a = push_ast(s, ast_namespace);
		if (!require(s, tok_identifier, "Namespace name identifier")) return NULL;
		a->namespace_.name = s->prev_token;
		a->namespace_.stmt = parse_toplevel(s);
		break;

	case tok_kw_extern:
		a = push_ast(s, ast_extern);
		if (!require(s, tok_string, "Extern context name string")) return NULL;
		a->extern_.format = s->prev_token;
		a->extern_.stmt = parse_toplevel(s);
		break;

	default:
		unlex(s);
		a = parse_free_statement(s);
		if (a == NULL && !s->error) {
			error_at(s, s->prev_token, "Expected a free statement");
		}
		break;
	}

	return s->error ? NULL : a;
}

ast **parse(compiler_state *s) {
	ast **stmts = NULL;

	lex(s);

	while (accept(s, '\n')) { }
	while (!accept(s, tok_end) && !s->error) {
		ast *a = parse_toplevel(s);
		buf_push(stmts, a);

		while (accept(s, '\n')) { }
	}

	return stmts;
}

void dump_ast_mods(FILE *f, unsigned mods) {
	if (mods & mod_inline) fputs("inline ", f);
	if (mods & mod_unsafe) fputs("unsafe ", f);
}

void dump_ast_name(FILE *f, ast *a) {
	switch (a->kind) {

	case ast_identifier:
		fputs(a->identifier.name.str, f);
		break;

	case ast_generic:
		dump_ast_name(f, a->generic.name);
		fputc('[', f);
		for (unsigned i = 0; i < buf_len(a->generic.args); i++) {
			if (i != 0) fputs(", ", f);
			assert(a->generic.args[i]->kind == ast_identifier);
			fputs(a->generic.args[i]->identifier.name.str, f);
		}
		fputc(']', f);
		break;

	default:
		assert(0 && "Unexpected AST type");
	}
}

void dump_ast_type(FILE *f, ast *a) {
	switch (a->kind) {

	case ast_identifier:
		fputs(a->identifier.name.str, f);
		break;

	case ast_member:
		dump_ast_type(f, a->member.left);
		putc('.', f);
		fputs(a->member.name.str, f);
		break;

	case ast_generic:
		dump_ast_type(f, a->generic.name);
		fputc('[', f);
		for (unsigned i = 0; i < buf_len(a->generic.args); i++) {
			if (i != 0) fputs(", ", f);
			dump_ast_type(f, a->generic.args[i]);
		}
		fputc(']', f);
		break;

	case ast_ref:
		fputc('*', f);
		dump_ast_type(f, a->ref.decl);
		break;

	default:
		assert(0 && "Unexpected AST type");
	}
}

void dump_ast_decl(FILE *f, ast *a) {
	assert(a->kind == ast_decl);

	fputs(a->decl.name.str, f);
	fputs(": ", f);
	dump_ast_type(f, a->decl.type);
}

void dump_indent(FILE *f, int indent) {
	for (int i = 0; i < indent * 2; i++) {
		putc(' ', f);
	}
}

void dump_ast_free_statement(FILE *f, int indent, ast* a);

void dump_ast_expr(FILE *f, int indent, ast* a) {
	switch (a->kind) {

	case ast_block:
		fputs("{\n", f);
		indent++;

		for (unsigned i = 0; i < buf_len(a->block.stmts); i++) {
			dump_indent(f, indent);
			dump_ast_expr(f, indent, a->block.stmts[i]);
			putc('\n', f);
		}
		indent--;

		dump_indent(f, indent);
		putc('}', f);
		break;

	case ast_if:
		for (unsigned i = 0; i < buf_len(a->if_.conds); i++) {
			if (i > 0) {
				putc('\n', f);
				dump_indent(f, indent);
				fputs("else ", f);
			}
			fputs("if (", f);
			dump_ast_expr(f, indent, a->if_.conds[i]);
			fputs(") ", f);
			dump_ast_expr(f, indent, a->if_.bodies[i]);
		}

		if (a->if_.else_body) {
			putc('\n', f);
			dump_indent(f, indent);
			fputs("else ", f);
			dump_ast_expr(f, indent, a->if_.else_body);
		}
		break;

	case ast_while:
		fputs("while (", f);
		dump_ast_expr(f, indent, a->while_.cond);
		fputs(") ", f);
		dump_ast_expr(f, indent, a->while_.body);
		break;

	case ast_paren:
		putc('(', f);
		dump_ast_expr(f, indent, a->paren.expr);
		putc(')', f);
		break;

	case ast_binop:
		dump_ast_expr(f, indent, a->binop.left);
		putc(' ', f);
		fputs(a->binop.op.str, f);
		putc(' ', f);
		dump_ast_expr(f, indent, a->binop.right);
		break;

	case ast_assign:
		dump_ast_expr(f, indent, a->assign.left);
		putc(' ', f);
		fputs(a->assign.op.str, f);
		putc(' ', f);
		dump_ast_expr(f, indent, a->assign.right);
		break;

	case ast_unop:
		fputs(a->unop.op.str, f);
		dump_ast_expr(f, indent, a->unop.arg);
		break;

	case ast_identifier:
		fputs(a->identifier.name.str, f);
		break;

	case ast_number:
		fputs(a->number.value.str, f);
		break;

	case ast_generic:
		dump_ast_expr(f, indent, a->generic.name);
		fputc('[', f);
		for (unsigned i = 0; i < buf_len(a->generic.args); i++) {
			if (i != 0) fputs(", ", f);
			dump_ast_type(f, a->generic.args[i]);
		}
		fputc(']', f);
		break;

	case ast_call:
		dump_ast_expr(f, indent, a->call.left);
		fputc('(', f);
		for (unsigned i = 0; i < buf_len(a->call.args); i++) {
			if (i != 0) fputs(", ", f);
			dump_ast_expr(f, indent, a->call.args[i]);
		}
		fputc(')', f);
		break;

	case ast_member:
		dump_ast_expr(f, indent, a->member.left);
		putc('.', f);
		fputs(a->member.name.str, f);
		break;

	case ast_new:
		fputs("new", f);
		if (a->new_.type) {
			fputc(' ', f);
			dump_ast_type(f, a->new_.type);
		}

		if (a->new_.args) {
			fputs(" { ", f);
			for (unsigned i = 0; i < buf_len(a->new_.args); i++) {
				if (i != 0) {
					fputs(", ", f);
				}

				dump_ast_expr(f, indent, a->new_.args[i]);
			}
			fputs(" }", f);
		}
		break;

	default:
		dump_ast_free_statement(f, indent, a);
	}
}

void dump_ast_free_statement(FILE *f, int indent, ast* a) {
	switch (a->kind) {

	case ast_block:
		fputs("{\n", f);
		indent++;

		for (unsigned i = 0; i < buf_len(a->block.stmts); i++) {
			dump_indent(f, indent);
			dump_ast_free_statement(f, indent, a->block.stmts[i]);
			putc('\n', f);
			putc('\n', f);
		}
		indent--;

		dump_indent(f, indent);
		putc('}', f);
		break;

	case ast_typedecl:
		dump_ast_mods(f, a->typedecl.mods);
		fputs("type ", f);
		dump_ast_name(f, a->typedecl.name);
		if (a->typedecl.init) {
			fputs(" = ", f);
			dump_ast_type(f, a->typedecl.init);
		}
		break;

	case ast_vardecl:
		dump_ast_mods(f, a->vardecl.mods);
		printf("%s %s", a->vardecl.kind.str, a->vardecl.name.str);
		if (a->vardecl.type) {
			fputs(": ", f);
			dump_ast_type(f, a->vardecl.type);
		}
		if (a->vardecl.init) {
			fputs(" = ", f);
			dump_ast_expr(f, indent, a->vardecl.init);
		}
		break;

	case ast_def:
		dump_ast_mods(f, a->def.mods);
		fputs("def ", f);
		dump_ast_name(f, a->def.name);
		if (!a->def.no_parens) {
			putc('(', f);
			for (unsigned i = 0; i < buf_len(a->def.args); i++) {
				if (i != 0) fputs(", ", f);
				dump_ast_decl(f, a->def.args[i]);
			}
			putc(')', f);
		}
		if (a->def.ret) {
			fputs(": ", f);
			dump_ast_type(f, a->def.ret);
		}
		if (a->def.body) {
			fputs(" = ", f);
			dump_ast_expr(f, indent, a->def.body);
		}
		break;

	case ast_type:
		dump_ast_mods(f, a->type.mods);
		printf("%s ", a->type.kind.str);
		dump_ast_name(f, a->type.name);
		putc(' ', f);
		if (a->type.extends) {
			fputs("extends ", f);
			for (unsigned i = 0; i < buf_len(a->type.extends); i++) {
				if (i != 0) fputs(", ", f);
				dump_ast_type(f, a->type.extends[i]);
			}
			putc(' ', f);
		}
		fputs("{\n", f);
		indent++;

		for (unsigned i = 0; i < buf_len(a->type.stmts); i++) {
			if (i != 0) putc('\n', f);
			dump_indent(f, indent);
			dump_ast_free_statement(f, indent, a->type.stmts[i]);
			putc('\n', f);
		}

		indent--;
		dump_indent(f, indent);
		putc('}', f);
		break;

	default:
		assert(0 && "Unexpected AST type");
	}
}

void dump_ast_toplevel(FILE *f, int indent, ast *a) {
	switch (a->kind) {

	case ast_namespace:
		fprintf(f, "namespace %s ", a->namespace_.name.str);
		dump_ast_toplevel(f, indent, a->namespace_.stmt);
		break;

	case ast_extern:
		fprintf(f, "extern %s ", a->extern_.format.str);
		dump_ast_toplevel(f, indent, a->extern_.stmt);
		break;

	default:
		dump_ast_free_statement(f, indent, a);
		break;

	}
}

void dump_ast(FILE *f, ast** a) {
	for (unsigned i = 0; i < buf_len(a); i++) {
		if (i != 0) putc('\n', f);
		dump_ast_toplevel(f, 0, a[i]);
		putc('\n', f);
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
	add_keyword(s, "while", tok_kw_while);
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

	ast **as = parse(s);

	if (s->error) {
		printf("Error: %s\n", s->error);
		printf("%s\n%s\n", s->errorline[0], s->errorline[1]);
	} else {
		dump_ast(stdout, as);
	}

	getchar();
	return 0;
}
