#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char Byte;
typedef bool Bool;
typedef int Int;

template <typename T>
struct Seq {

	Seq()
		: data(nullptr)
		, count(0)
	{ }

	Seq(T *data, size_t count)
		: data(data)
		, count(count)
	{ }

	T operator[](Int index) {
		return data[index];
	}

	T *data;
	ptrdiff_t count;
};


typedef Seq<Byte> String;

String str(const char *s) {
	Byte *b = (Byte*)s;
	return String(b, strlen(s));
}

extern "C" {

unsigned char *readFileBytes(char *filename, int *length) {
	FILE *f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);
	fseek(f, 0, SEEK_SET);
	*length = (int)size;
	unsigned char *data = (unsigned char*)malloc(size);
	fread(data, 1, size, f);
	fclose(f);
	return data;
}

void printLine(char *message, int length) {
	fprintf(stderr, "%s\n", message);
}

void fail() {
	__debugbreak();
}

}

struct SourceFile {
	Seq<Byte> data;
	Int position;
};

struct Token {
	SourceFile *file;
	Int type;
	Int begin, end;
};

const Int TokIdent = 1001;
const Int TokString = 1002;
const Int TokNumber = 1003;

const Int TokPostEq = 2000;
const Int TokAddAssign = TokPostEq + '+';
const Int TokSubAssign = TokPostEq + '-';
const Int TokMulAssign = TokPostEq + '*';;
const Int TokDivAssign = TokPostEq + '/';
const Int TokEqual = TokPostEq + '=';
const Int TokNotEqual = TokPostEq + '!';
const Int TokLessEqual = TokPostEq + '<';
const Int TokGreaterEqual = TokPostEq + '>';

const Int TokAnd = 3001;
const Int TokOr = 3001;

void loadFile(SourceFile *f, String filename) {
	Byte cstr[1024];
	for (Int i = 0; i < filename.count; i += 1) {
		cstr[i] = filename[i];
	}
	cstr[filename.count] = 0;

	Int length = 0;
	Byte *bytes = readFileBytes((char*)cstr, &length);

	f->data = Seq<Byte>(bytes, length);
	f->position = 0;
}

Byte peek(SourceFile *f) {
	if (f->position < f->data.count) {
		return f->data[f->position];
	} else {
		return 0;
	}
}

Byte eat(SourceFile *f) {
	if (f->position < f->data.count) f->position += 1;
	return peek(f);
}

Bool range(Byte c, Seq<Byte> bounds) { return c >= bounds[0] && c <= bounds[1]; }

void error(Token token, String message) {
	printLine((char*)message.data, (int)message.count);
	fail();
}

Bool contained(Byte c, Seq<Byte> options) {
	for (Int i = 0; i < options.count; i += 1) {
		if (c == options[i]) return true;
	}
	return false;
}

Token lex(SourceFile *f) {
	Byte c = peek(f);

whitespace:
	while (c == ' ' || c == '\t' || c == '\r') {
		c = eat(f);
	}

	Token tok;
	tok.file = f;
	tok.begin = f->position;

	if (c == '/') {
		Byte la = eat(f);
		if (la == '/') {
			do {
				c = eat(f);
			} while(c != '\n' && c != '\0');
			goto whitespace;
		} else if (la == '=') {
			tok.type = '/';
			goto accept;
		} else {
			tok.type = TokDivAssign;
			goto accept;
		}
	}

	if (range(c, str("AZ")) || range(c, str("az")) || c == '_') {
		do {
			c = eat(f);
		} while (range(c, str("AZ")) || range(c, str("az")) || range(c, str("09")) || c == '_');

		if (c == '\"') {
			goto string;
		} else {
			tok.type = TokIdent;
			goto accept;
		}
	}

	if (range(c, str("09"))) {
		do {
			c = eat(f);
		} while (range(c, str("09")));

		tok.type = TokNumber;
		goto accept;
	}

string:
	if (c == '\"') {
		do {
			c = eat(f);
			if (c == '\\') {
				if (eat(f) == 0) error(tok, str("Expected an escape sequence"));
			}
			if (c == '\n') error(tok, str("Newline in string"));
		} while (c != '\"' && c != '\0');

		if (c != '\"') {
			error(tok, str("String not closed"));
		} else {
			eat(f);
			tok.type = TokString;
			goto accept;
		}

	}

	Int la = eat(f);
	if (contained(c, str(".,:;()[]{};\n")) || c == '\0') {
		tok.type = c;
	} else if (contained(c, str("+-/*!=<>"))) {
		if (la == '=') {
			tok.type = TokPostEq + c;
		} else {
			tok.type = c;
		}
	} else if (c == '&') {
		tok.type = (la == c)? TokAnd : c;
	} else if (c == '|') {
		tok.type = (la == c) ? TokOr : c;
	} else {
		error(tok, str("Unexpected character"));
	}

accept:
	tok.end = f->position;
	return tok;
}

int main(int argc, char **argv) {
	SourceFile file;
	loadFile(&file, str(argv[1]));

	Token tok;
	do {
		tok = lex(&file);
		printf("%d\n", tok.type);
	} while (tok.type != '\0');

	return 0;
}
