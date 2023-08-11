#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct Tokens        Tokens;
typedef struct ParsingResult ParsingResult;
typedef const char          *Error;
typedef struct Vla           Vla;
typedef struct Methods       Methods;
typedef struct Program       Program;
typedef struct TreeNode      TreeNode;
typedef struct NodeValue     NodeValue;
typedef enum NodeKind        NodeKind;

static const char *null_ptr_terminator = NULL;
static const char  null_terminator     = '\0';

static const char E_PARSE_ERROR[]  = "error: parse";
static const char E_SYS_ERROR[]    = "error: fatal";
static const char E_EXEC_ERROR[]   = "error: cannot execute ";
static const char E_CD_ERROR[]     = "error: cd: cannot change directory to ";
static const char E_CD_ARG_ERROR[] = "error: cd: bad arguments";

void *ft_xmalloc(size_t size);

enum NodeKind {
	ND_SEMICOLON,
	ND_PIPE,
	ND_CMD,
};

struct Methods
{
	void (*destructor)();
};

struct Tokens
{
	char **value;
};

struct Vla
{
	Methods methods;
	void   *buf;
	size_t  size;
	size_t  cap;
	size_t  elem_size;
};

struct TreeNode
{
	void     *value;
	TreeNode *left;
	TreeNode *right;
};

struct NodeValue
{
	Methods  methods;
	NodeKind kind;
	char   **value;
};

struct Program
{
	Methods    methods;
	TreeNode **statements;
};

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
		printf("%s ", "{|}");
		print_node(node->right);
	} else if (nv->kind == ND_SEMICOLON) {
		printf("%s ", "{;}");
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

void destruct(void *target)
{
	Methods *m = target;

	if (!m || !m->destructor) {
		return;
	}
	m->destructor(target);
}

Vla construct_vla(size_t elem_size, void (*destructor)())
{
	Vla vla;
	vla.buf                = ft_xmalloc(elem_size * 1);
	vla.size               = 0;
	vla.cap                = 1;
	vla.elem_size          = elem_size;
	vla.methods.destructor = destructor;
	return vla;
}

void destruct_vla(Vla *vla)
{
	free(vla->buf);
	vla->buf  = NULL;
	vla->cap  = 0;
	vla->size = 0;
}

void *ft_memcpy(void *dest, const void *src, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		((unsigned char *)dest)[i] = ((const unsigned char *)src)[i];
	}
	return dest;
}

void expand_buf_if_needed(Vla *vla)
{
	if (vla->size < vla->cap) {
		return;
	}
	void  *old_buf = vla->buf;
	size_t new_cap = vla->cap * 2;
	void  *new_buf = ft_xmalloc(new_cap * vla->elem_size);
	ft_memcpy(new_buf, old_buf, vla->size * vla->elem_size);
	vla->buf = new_buf;
	vla->cap = new_cap;
	free(old_buf);
}

void push_back(Vla *vla, const void *data_ptr)
{
	expand_buf_if_needed(vla);
	void *pos = vla->buf + (vla->size * vla->elem_size);
	ft_memcpy(pos, data_ptr, vla->elem_size);
	vla->size++;
}

void push_back_string(Vla *vla, const char *s)
{
	while (*s) {
		const char c = *s;
		push_back(vla, &c);
		s++;
	}
}

void ft_perror(const char **strs)
{
	Vla joined = construct_vla(sizeof(char), destruct_vla);

	while (*strs) {
		push_back_string(&joined, *strs);
		++strs;
	}
	push_back_string(&joined, "\n");
	write(STDERR_FILENO, joined.buf, joined.size);
	destruct(&joined);
}

void *ft_xmalloc(size_t size)
{
	void *p = malloc(size);
	if (!p) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return p;
}

char *ft_xstrdup(const char *src)
{
	Vla s = construct_vla(sizeof(char), NULL);

	push_back_string(&s, src);
	push_back(&s, &null_terminator);
	return s.buf;
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

void delete(void *target)
{
	destruct(target);
	free(target);
}

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

void destruct_node_vla(Vla *vla)
{
	TreeNode **nodes = vla->buf;

	for (size_t i = 0; i < vla->size; i++) {
		delete_subtree(nodes[i], delete);
		nodes[i] = NULL;
	}
	destruct_vla(vla);
}

void destruct_node_value(NodeValue *nv)
{
	if (!nv->value) {
		return;
	}
	for (size_t i = 0; nv->value[i]; i++) {
		free(nv->value[i]);
		nv->value[i] = NULL;
	}
	free(nv->value);
	nv->value = NULL;
}

bool is_empty(const Tokens *tokens)
{
	return !tokens->value || tokens->value[0] == NULL;
}

TreeNode *create_node(void *value, TreeNode *left, TreeNode *right)
{
	TreeNode *node = ft_xmalloc(sizeof(TreeNode));
	node->value    = value;
	node->left     = left;
	node->right    = right;
	return node;
}

NodeValue *create_node_value(NodeKind kind, char **value, void (*destrucor)())
{
	NodeValue *nv          = ft_xmalloc(sizeof(NodeValue));
	nv->kind               = kind;
	nv->value              = value;
	nv->methods.destructor = destrucor;
	return nv;
}

TreeNode *create_operator_node(NodeKind kind, TreeNode *left, TreeNode *right)
{
	NodeValue *nv = create_node_value(kind, NULL, NULL);
	return create_node(nv, left, right);
}

char **clone_commands(char **cmds)
{
	if (!cmds) {
		return NULL;
	}
	Vla vla = construct_vla(sizeof(char *), NULL);
	while (*cmds) {
		char *cmd = ft_xstrdup(*cmds);
		push_back(&vla, &cmd);
		cmds++;
	}
	push_back(&vla, &null_ptr_terminator);
	return vla.buf;
}

TreeNode *create_cmd_node(char **value)
{
	char     **content = clone_commands(value);
	NodeValue *nv      = create_node_value(ND_CMD, content, destruct_node_value);
	return create_node(nv, NULL, NULL);
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

TreeNode *parse_command(Tokens *tokens)
{
	char *word = consume_cmd(tokens);
	if (!word) {
		return NULL;
	}
	Vla cmd = construct_vla(sizeof(char *), destruct_vla);

	while (true) {
		push_back(&cmd, &word);
		word = consume_cmd(tokens);
		if (!word) {
			push_back(&cmd, &null_ptr_terminator);
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
		TreeNode *statement = parse_statement(tokens);
		if (!statement) {
			destruct(&program);
			return NULL;
		}
		push_back(&program, &statement);
	}
	push_back(&program, &null_ptr_terminator);
	return program.buf;
}

ParsingResult parse(Tokens tokens)
{
	Program p = {.methods.destructor = destruct_program};

	p.statements = parse_program(&tokens);
	if (!p.statements) {
		return (ParsingResult){.err = E_PARSE_ERROR};
	}
	return (ParsingResult){.program = p};
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
	new_fd = dup2(old_fd, new_fd);
	if (new_fd == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return new_fd;
}

void xclose(int fd)
{
	if (close(fd) == -1) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
}

void xpipe(int *fds)
{
	if (pipe(fds) == -1) {
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

pid_t xwaitpid(pid_t pid, int *status, int option)
{
	pid = waitpid(pid, status, option);
	if (pid == -1 && errno != EINTR && errno != ECHILD) {
		ft_perror((const char *[]){E_SYS_ERROR, NULL});
		exit(1);
	}
	return pid;
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

int waitpid_all(pid_t last_pid)
{
	int last_status;

	while (true) {
		int   status = 0;
		pid_t pid    = xwaitpid(0, &status, 0);
		if (pid == -1 && errno == EINTR) {
			continue;
		}
		if (pid == -1 && errno == ECHILD) {
			break;
		}
		if (pid == last_pid) {
			last_status = status;
		}
	}
	return last_status;
}

int cd(char **argv)
{
	if (!argv || !argv[1] || argv[2]) {
		ft_perror((const char *[]){E_CD_ARG_ERROR, NULL});
		return 1;
	}
	if (chdir(argv[1]) == -1) {
		ft_perror((const char *[]){E_CD_ERROR, argv[1], NULL});
		return 1;
	}
	return 0;
}

pid_t exec_command(char **argv, int input_fd)
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

pid_t eval_command(const TreeNode *node, int input_fd, void (*setup_io_fd)(int input_fd))
{
	int saved_stdin  = xdup(STDIN_FILENO);
	int saved_stdout = xdup(STDOUT_FILENO);
	setup_io_fd(input_fd);
	const NodeValue *nv  = node->value;
	pid_t            pid = exec_command(nv->value, input_fd);
	xdup2(saved_stdin, STDIN_FILENO);
	xdup2(saved_stdout, STDOUT_FILENO);
	xclose(saved_stdin);
	xclose(saved_stdout);
	return pid;
}

pid_t eval_expr(const TreeNode *expr, int input_fd, void (*setup_io_fd)(int input_fd));

pid_t eval_pipe(const TreeNode *node, int input_fd, void (*setup_io_fd)(int input_fd))
{
	eval_expr(node->left, input_fd, setup_io_fd_for_pipe);
	return eval_expr(node->right, input_fd, setup_io_fd);
}

pid_t eval_expr(const TreeNode *expr, int input_fd, void (*setup_io_fd)(int input_fd))
{
	NodeValue *nv = expr->value;

	switch (nv->kind) {
	case ND_PIPE:
		return eval_pipe(expr, input_fd, setup_io_fd);
	case ND_CMD:
		return eval_command(expr, input_fd, setup_io_fd);
	default:
		exit(2); // NOT REACH
	}
}

int eval_statement(const TreeNode *statement)
{
	if (!statement->left) {
		return 0;
	}
	int   input_fd = xdup(STDIN_FILENO);
	pid_t last_pid = eval_expr(statement->left, input_fd, setup_io_fd_for_last);
	xclose(input_fd);
	return waitpid_all(last_pid);
}

bool is_single_builtin(const TreeNode *statement)
{
	if (!statement) {
		return false;
	}
	const TreeNode *cmd_node      = statement->left;
	bool            is_single_cmd = cmd_node && !cmd_node->right && !cmd_node->left;
	if (!is_single_cmd) {
		return false;
	}
	const NodeValue *nv = statement->left->value;
	if (!nv->value) {
		return false;
	}
	return strcmp(nv->value[0], "cd") == 0;
}

int exec_single_builtin(const TreeNode *statement)
{
	const NodeValue *nv = statement->left->value;
	return cd(nv->value);
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
		return 1;
	}
	Tokens        tokens = (Tokens){.value = argv + 1};
	ParsingResult res    = parse(tokens);
	if (res.err != NULL) {
		return 1;
	}
	// print(&res.program);
	int status = exec(&res.program);
	destruct(&res.program);
	return status;
}
