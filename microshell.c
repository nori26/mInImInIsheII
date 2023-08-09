#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
	<PROGRAM>        = <STATEMENT>* <LAST_STATEMENT> "\n"
	<STATEMENT>      = <PIPELINE> ";"
	<LAST_STATEMENT> = <PIPELINE> ";"?
	<PIPELINE>       = <PROCESS> ("|" <PROCESS>)*
	<PROCESS>        = <CMD>
*/

typedef const char          *Error;
typedef struct TreeNode      TreeNode;
typedef struct NodeValue     NodeValue;
typedef struct Program       Program;
typedef struct Tokens        Tokens;
typedef struct ParsingResult ParsingResult;

static const Error E_PARSE_ERROR  = "parse error";
static const Error E_SYS_ERROR    = "error: fatal";
static const Error E_EXEC_ERROR   = "error: cannot execute ";
static const Error E_CD_ERROR     = "error: cd: cannot change directory to ";
static const Error E_CD_ARG_ERROR = "error: cd: bad arguments";

char *join_strs(const char **strs);

size_t ft_strlen(const char *s)
{
	size_t i = 0;

	while (s[i]) {
		i++;
	}
	return i;
}

void ft_perror(const char **strs)
{
	char *s    = join_strs(strs);
	char *endl = join_strs((const char *[]){s, "\n", NULL});
	write(STDERR_FILENO, endl, ft_strlen(endl));
	free(s);
	free(endl);
}

void *ft_xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return p;
}

char *ft_xstrdup(const char *src)
{
	const size_t size = ft_strlen(src) + 1;
	char        *s    = ft_xmalloc(size);
	for (size_t i = 0; i < size; i++) {
		s[i] = src[i];
	}
	return s;
}

void *ft_memcpy(void *dest, const void *src, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		((unsigned char *)dest)[i] = ((unsigned char *)src)[i];
	}
	return dest;
}

int xdup(int fd)
{
	int new_fd = dup(fd);
	if (new_fd == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return new_fd;
}

int xdup2(int old_fd, int new_fd)
{
	int res = dup2(old_fd, new_fd);
	if (res == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return res;
}

void xclose(int fd)
{
	if (close(fd) == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
}

pid_t xfork()
{
	pid_t pid = fork();
	if (pid == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return pid;
}

void xpipe(int *fds)
{
	if (pipe(fds) == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
}

pid_t xwaitpid(pid_t pid, int *raw_status, int options)
{
	pid = waitpid(pid, raw_status, options);
	if (pid < 0 && errno != ECHILD && errno != EINTR) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return pid;
}

typedef enum {
	ND_SEMICOLON,
	ND_PIPE,
	ND_CMD,
} NodeKind;

typedef struct Methods
{
	void (*destructor)();
} Methods;

void destruct(void *target)
{
	const Methods *m = (Methods *)target;
	if (!m || !m->destructor) {
		return;
	}
	m->destructor(target);
}

void delete(void *target)
{
	destruct(target);
	free(target);
}

struct TreeNode
{
	void     *value;
	TreeNode *left;
	TreeNode *right;
};

TreeNode *create_node(void *value, TreeNode *left, TreeNode *right)
{
	TreeNode *node = ft_xmalloc(sizeof(TreeNode));
	node->value    = value;
	node->left     = left;
	node->right    = right;
	return node;
}

void delete_subtree(TreeNode *node, void (*del)())
{
	if (!node) {
		return;
	}
	TreeNode *left  = node->left;
	TreeNode *right = node->right;
	del(node->value);
	free(node);
	delete_subtree(left, del);
	delete_subtree(right, del);
}

typedef struct Vla
{
	Methods methods;
	void   *buf;
	size_t  size;
	size_t  cap;
} Vla;

Vla construct_vla(size_t elem_size, void (*destructor)())
{
	Vla v;
	v.buf                = ft_xmalloc(elem_size * 1);
	v.cap                = 1;
	v.size               = 0;
	v.methods.destructor = destructor;
	return v;
}

void expand_buf_if_needed(Vla *vla, size_t elem_size)
{
	if (vla->size < vla->cap) {
		return;
	}
	size_t new_cap = vla->cap * 2;
	void  *new_buf = ft_xmalloc(elem_size * new_cap);
	ft_memcpy(new_buf, vla->buf, vla->size * elem_size);
	free(vla->buf);
	vla->buf = new_buf;
	vla->cap = new_cap;
}

void push_back(Vla *vla, void *p)
{
	expand_buf_if_needed(vla, sizeof(void *));
	((void **)vla->buf)[vla->size++] = p;
}

void push_back_char(Vla *vla, char c)
{
	expand_buf_if_needed(vla, sizeof(char));
	((char *)vla->buf)[vla->size++] = c;
}

void destruct_vla(Vla *vla)
{
	free(vla->buf);
	vla->buf = NULL;
}

void destruct_node_vla(Vla *vla)
{
	TreeNode **n = vla->buf;
	for (size_t i = 0; i < vla->size; i++) {
		delete_subtree(n[i], delete);
		n[i] = NULL;
	}
	free(vla->buf);
	vla->buf = NULL;
}

char *join_strs(const char **strs)
{
	Vla joined = construct_vla(sizeof(char), NULL);

	for (; *strs; strs++) {
		for (char *s = *strs; *s; s++) {
			push_back_char(&joined, *s);
		}
	}
	push_back_char(&joined, '\0');
	return joined.buf;
}

struct NodeValue
{
	Methods  methods;
	NodeKind kind;
	char   **value;
};

void destruct_node_value(NodeValue *nv)
{
	for (char **value = nv->value; value && *value; value++) {
		free(*value);
		*value = NULL;
	}
	free(nv->value);
	nv->value = NULL;
}

void *clone_value(char **value)
{
	if (!value) {
		return NULL;
	}
	Vla cmd = construct_vla(sizeof(char *), NULL);
	while (*value) {
		push_back(&cmd, ft_xstrdup(*value));
		value++;
	}
	push_back(&cmd, NULL);
	return cmd.buf;
}

NodeValue *create_node_value(NodeKind kind, char **value)
{
	NodeValue *nv          = ft_xmalloc(sizeof(NodeValue));
	nv->methods.destructor = destruct_node_value;
	nv->kind               = kind;
	nv->value              = clone_value(value);
	return nv;
}

struct Tokens
{
	char **value;
};

bool is_empty(Tokens *tokens)
{
	return tokens->value[0] == NULL;
}

struct Program
{
	Methods    methods;
	TreeNode **statements;
};

void destruct_program(Program *p)
{
	if (!p->statements) {
		return;
	}
	for (size_t i = 0; p->statements[i]; i++) {
		delete_subtree(p->statements[i], delete);
		p->statements[i] = NULL;
	}
	free(p->statements);
	p->statements = NULL;
}

struct ParsingResult
{
	Program program;
	Error   err;
};

void print_node(TreeNode *node)
{
	if (!node) {
		return;
	}
	print_node(node->left);
	NodeValue *nv = node->value;
	if (nv->kind == ND_CMD) {
		for (char **value = nv->value; *value; value++) {
			printf("{%s} ", *value);
		}
	} else if (nv->kind == ND_PIPE) {
		printf("%s", "{|}");
		print_node(node->right);
	} else if (nv->kind == ND_SEMICOLON) {
		printf("%s", "{;}");
		print_node(node->right);
	}
}

void print(Program *p)
{
	if (!p->statements) {
		return;
	}
	for (size_t i = 0; p->statements[i]; i++) {
		print_node(p->statements[i]);
		puts("");
	}
}

char *consume(Tokens *tokens, const char *kind)
{
	if (!*tokens->value || strcmp(*tokens->value, kind) != 0) {
		return NULL;
	}
	return *tokens->value++;
}

char *consume_cmd(Tokens *tokens)
{
	if (!*tokens->value || strcmp(*tokens->value, ";") == 0 || strcmp(*tokens->value, "|") == 0) {
		return NULL;
	}
	return *tokens->value++;
}

TreeNode *create_cmd_node(char **cmd)
{
	NodeValue *nv = create_node_value(ND_CMD, cmd);
	return create_node(nv, NULL, NULL);
}

TreeNode *create_operator_node(NodeKind kind, TreeNode *left, TreeNode *right)
{
	NodeValue *nv = create_node_value(kind, NULL);
	return create_node(nv, left, right);
}

TreeNode *parse_command(Tokens *tokens)
{
	char *word = consume_cmd(tokens);
	if (!word) {
		return NULL;
	}
	Vla cmd = construct_vla(sizeof(char *), destruct_vla);

	while (true) {
		push_back(&cmd, word);
		word = consume_cmd(tokens);
		if (!word) {
			push_back(&cmd, NULL);
			TreeNode *node = create_cmd_node(cmd.buf);
			destruct(&cmd);
			return node;
		}
	}
}

TreeNode *parse_pipeline(Tokens *tokens)
{
	TreeNode *node = parse_command(tokens);
	if (!node) {
		return NULL;
	}
	while (true) {
		if (consume(tokens, "|")) {
			TreeNode *right = parse_command(tokens);
			if (!right) {
				delete_subtree(node, delete);
				return NULL;
			}
			node = create_operator_node(ND_PIPE, node, right);
		} else {
			return node;
		}
	}
}

TreeNode *parse_statement(Tokens *tokens)
{
	TreeNode *node = parse_pipeline(tokens);
	if (!node) {
		return NULL;
	}
	if (consume(tokens, ";") == NULL && !is_empty(tokens)) {
		delete_subtree(node, delete);
		return NULL;
	}
	return create_operator_node(ND_SEMICOLON, node, NULL);
}

TreeNode **parse_program(Tokens *tokens)
{
	Vla program = construct_vla(sizeof(TreeNode *), destruct_node_vla);

	while (!is_empty(tokens)) {
		TreeNode *node = parse_statement(tokens);
		if (!node) {
			destruct(&program);
			return NULL;
		}
		push_back(&program, node);
	}
	push_back(&program, NULL);
	return program.buf;
}

ParsingResult parse(Tokens tokens)
{
	Program p = {.methods.destructor = destruct_program};

	p.statements = parse_program(&tokens);
	if (!p.statements) {
		destruct(&p);
		return (ParsingResult){.err = E_PARSE_ERROR};
	}
	return (ParsingResult){.program = p};
}

void setup_io_fd_for_pipe(int input_fd)
{
	int fds[2];

	xpipe(fds);
	xdup2(input_fd, STDIN_FILENO);
	xdup2(fds[1], STDOUT_FILENO);
	xdup2(fds[0], input_fd);
	xclose(fds[0]);
	xclose(fds[1]);
}

void setup_io_fd_for_last(int input_fd)
{
	xdup2(input_fd, STDIN_FILENO);
}

pid_t eval_expr(const TreeNode *node, int input_fd, void (*setup_io_fd)(int input_fd));

pid_t eval_pipe(const TreeNode *node, int input_fd, void (*setup_io_fd)(int input_fd))
{
	eval_expr(node->left, input_fd, setup_io_fd_for_pipe);
	return eval_expr(node->right, input_fd, setup_io_fd);
}

int cd(char **argv)
{
	if (!argv[1] || argv[2]) {
		ft_perror((const char *[]){E_CD_ARG_ERROR, NULL});
		return 1;
	}
	if (chdir(argv[1]) == -1) {
		ft_perror((const char *[]){E_CD_ERROR, argv[1], NULL});
		return 1;
	}
	return 0;
}

pid_t exec_cmd(char **argv, int input_fd)
{
	pid_t pid = xfork();
	if (pid) {
		return pid;
	}
	extern char **environ;
	xclose(input_fd);
	if (strcmp(argv[0], "cd") == 0) {
		exit(cd(argv));
	} else {
		execve(argv[0], argv, environ);
		ft_perror((const char *[]){E_EXEC_ERROR, argv[0], NULL});
		exit(1);
	}
}

bool is_single_builtin(const TreeNode *statement)
{
	bool has_cmd = statement && !statement->right && statement->left;
	if (!has_cmd) {
		return false;
	}
	const TreeNode *cmd_node      = statement->left;
	bool            is_single_cmd = !cmd_node->left && !cmd_node->right;
	if (!is_single_cmd) {
		return false;
	}
	const NodeValue *v = cmd_node->value;
	if (!v->value) {
		return false;
	}
	return strcmp(v->value[0], "cd") == 0;
}

pid_t eval_cmd(const TreeNode *node, int input_fd, void (*setup_io_fd)(int input_fd))
{
	const NodeValue *v            = node->value;
	int              saved_stdin  = xdup(STDIN_FILENO);
	int              saved_stdout = xdup(STDOUT_FILENO);
	setup_io_fd(input_fd);
	pid_t pid = exec_cmd(v->value, input_fd);
	xdup2(saved_stdin, STDIN_FILENO);
	xdup2(saved_stdout, STDOUT_FILENO);
	xclose(saved_stdin);
	xclose(saved_stdout);
	return pid;
}

pid_t eval_expr(const TreeNode *node, int input_fd, void (*setup_io_fd)(int input_fd))
{
	const NodeValue *v = node->value;

	switch (v->kind) {
	case ND_PIPE:
		return eval_pipe(node, input_fd, setup_io_fd);
	case ND_CMD:
		return eval_cmd(node, input_fd, setup_io_fd);
	default:
		exit(2); // NOT REACH
	}
}

int waitpid_all(pid_t last_pid)
{
	int   exit_status;
	pid_t pid;

	while (true) {
		int status;
		pid = xwaitpid(-1, &status, 0);
		if (pid == -1 && errno == EINTR) {
			continue;
		} else if (pid == -1 && errno == ECHILD) {
			break;
		}
		if (pid != 0 && pid == last_pid) {
			exit_status = status;
		}
	}
	return exit_status;
}

int eval_statement(const TreeNode *node)
{
	int   fd       = dup(STDIN_FILENO);
	pid_t last_pid = eval_expr(node->left, fd, setup_io_fd_for_last);
	xclose(fd);
	return waitpid_all(last_pid);
}

int exec_single_builtin(const TreeNode *node)
{
	const NodeValue *v = node->left->value;
	return cd(v->value);
}

int exec(const Program *program)
{
	if (!program || !program->statements) {
		return 1;
	}
	int exit_status = 0;
	for (size_t i = 0; program->statements[i]; i++) {
		const TreeNode *statement = program->statements[i];
		if (is_single_builtin(statement)) {
			exit_status = exec_single_builtin(statement);
		} else {
			exit_status = eval_statement(statement);
		}
	}
	return exit_status;
}

int main(int argc, char **argv)
{
	if (argc <= 1) {
		return 0;
	}
	Tokens        tokens = (Tokens){.value = argv + 1};
	ParsingResult res    = parse(tokens);
	if (res.err != NULL) {
		// ft_perror((const char *[]){res.err, NULL});
		return 1;
	}
	// print(&res.program);
	int status = exec(&res.program);
	destruct(&res.program);
	return status;
}
