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
	{ "htm",   "text/html; charset=UTF-8" },
	{ "css",   "text/css" },
	{ "txt",   "text/plain" },
	{ "text",  "text/plain" },
	{ "md",    "text/plain" },
	{ "c",     "text/plain" },
	{ "h",     "text/plain" },
	{ "gz",    "application/x-gtar" },
	{ "tar",   "application/tar" },
	{ "pdf",   "application/x-pdf" },
	{ "png",   "image/png" },
	{ "gif",   "image/gif" },
	{ "jpg",   "image/jpg" },
	{ "iso",   "application/x-iso9660-image" },
	{ "webp",  "image/webp" },
	{ "svg",   "image/svg+xml" },
	{ "flac",  "audio/flac" },
	{ "mp3",   "audio/mpeg" },
	{ "mp4",   "video/mp4" },
	{ "ogv",   "video/ogg" },
	{ "webm",  "video/webm" },
};
