static const char *host      = "127.0.0.1";
static const char *port      = "80";
static const char *servedir  = ".";
static const char *docindex  = "index.html";
static const int   listdirs  = 1;
static const char *user      = "nobody";
static const char *group     = "nogroup";
static const int   maxnprocs = 512;

#define MAXREQLEN 4096 /* >= 4 */

static const struct {
	char *ext;
	char *type;
} mimes[] = {
	{ "xml",   "application/xml" },
	{ "xhtml", "application/xhtml+xml" },
	{ "html",  "text/html; charset=UTF-8" },
	{ "html",  "text/html; charset=UTF-8" },
	{ "htm",   "text/html; charset=UTF-8" },
	{ "css",   "text/css" },
	{ "txt",   "text/plain" },
	{ "text",  "text/plain" },
	{ "md",    "text/plain" },
	{ "png",   "image/png" },
	{ "gif",   "image/gif" },
	{ "jpg",   "image/jpg" },
	{ "c",     "text/plain" },
	{ "h",     "text/plain" },
	{ "iso",   "application/x-iso9660-image" },
	{ "gz",    "application/x-gtar" },
	{ "pdf",   "application/x-pdf" },
	{ "tar",   "application/tar" },
	{ "mp3",   "audio/mp3" },
};
