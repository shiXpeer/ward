// Package productid contains explicit, reviewable upstream identity mappings.
// No fuzzy names, network discovery or inference from a version string is used.
package productid

// Formula keys must be core formula identities. Versioned variants are listed
// explicitly; arbitrary taps and forks are not mapped to upstream products.
var Formula = map[string]string{
	"openssl@3": "a:openssl:openssl", "openssl@1.1": "a:openssl:openssl",
	"curl": "a:haxx:curl", "wget": "a:gnu:wget", "git": "a:git-scm:git",
	"xz": "a:tukaani:xz", "zstd": "a:facebook:zstandard", "lz4": "a:lz4:lz4",
	"libpng": "a:libpng:libpng", "jpeg-turbo": "a:libjpeg-turbo:libjpeg-turbo",
	"libtiff": "a:libtiff:libtiff", "freetype": "a:freetype:freetype2",
	"harfbuzz": "a:harfbuzz_project:harfbuzz", "fontconfig": "a:fontconfig_project:fontconfig",
	"libxml2": "a:xmlsoft:libxml2", "expat": "a:libexpat:libexpat", "libxslt": "a:xmlsoft:libxslt",
	"sqlite": "a:sqlite:sqlite", "nginx": "a:f5:nginx", "httpd": "a:apache:http_server",
	"redis": "a:redis:redis", "valkey": "a:valkey-io:valkey", "memcached": "a:memcached:memcached",
	"postgresql@14": "a:postgresql:postgresql", "postgresql@15": "a:postgresql:postgresql", "postgresql@16": "a:postgresql:postgresql", "postgresql@17": "a:postgresql:postgresql", "postgresql@18": "a:postgresql:postgresql",
	"mysql": "a:oracle:mysql", "mariadb": "a:mariadb:mariadb",
	"python@3.11": "a:python:python", "python@3.12": "a:python:python", "python@3.13": "a:python:python", "python@3.14": "a:python:python",
	"node": "a:nodejs:node.js", "node@20": "a:nodejs:node.js", "node@22": "a:nodejs:node.js", "node@24": "a:nodejs:node.js",
	"go": "a:golang:go", "php": "a:php:php", "php@8.2": "a:php:php", "php@8.3": "a:php:php", "php@8.4": "a:php:php",
	"ruby": "a:ruby-lang:ruby", "ffmpeg": "a:ffmpeg:ffmpeg", "imagemagick": "a:imagemagick:imagemagick",
	"openjdk": "a:oracle:openjdk", "openjdk@17": "a:oracle:openjdk", "openjdk@21": "a:oracle:openjdk",
	"gnutls": "a:gnu:gnutls", "libssh": "a:libssh:libssh", "libssh2": "a:libssh2:libssh2",
	"c-ares": "a:c-ares_project:c-ares", "nghttp2": "a:nghttp2:nghttp2", "brotli": "a:google:brotli",
	"glib": "a:gnome:glib", "pcre2": "a:pcre:pcre2", "libarchive": "a:libarchive:libarchive",
	"bzip2": "a:bzip:bzip2", "gmp": "a:gmplib:gmp", "gnupg": "a:gnupg:gnupg",
	"gpgme": "a:gnupg:gpgme", "libgcrypt": "a:gnupg:libgcrypt", "libgpg-error": "a:gnupg:libgpg-error",
	"unbound": "a:nlnetlabs:unbound", "bind": "a:isc:bind", "rsync": "a:samba:rsync",
	"tmux": "a:tmux:tmux", "vim": "a:vim:vim", "neovim": "a:neovim:neovim",
	"bash": "a:gnu:bash", "zsh": "a:zsh:zsh", "tar": "a:gnu:tar", "gzip": "a:gnu:gzip",
	"libwebp": "a:webmproject:libwebp", "libvpx": "a:webmproject:libvpx", "aom": "a:aomedia:aomedia_codec",
	"oniguruma": "a:oniguruma_project:oniguruma", "openexr": "a:openexr:openexr",
}
var Bundle = map[string]string{
	"com.google.Chrome": "a:google:chrome", "org.chromium.Chromium": "a:chromium:chromium",
	"org.mozilla.firefox": "a:mozilla:firefox", "org.mozilla.thunderbird": "a:mozilla:thunderbird",
	"com.microsoft.edgemac": "a:microsoft:edge", "com.brave.Browser": "a:brave:brave",
	"com.operasoftware.Opera": "a:opera:opera_browser", "org.videolan.vlc": "a:videolan:vlc_media_player",
	"com.microsoft.VSCode": "a:microsoft:visual_studio_code", "com.microsoft.Word": "a:microsoft:word",
	"com.microsoft.Excel": "a:microsoft:excel", "com.microsoft.Powerpoint": "a:microsoft:powerpoint",
	"com.microsoft.Outlook": "a:microsoft:outlook", "us.zoom.xos": "a:zoom:zoom",
	"org.wireshark.Wireshark": "a:wireshark:wireshark", "org.libreoffice.script": "a:libreoffice:libreoffice",
	"org.gimp.gimp-2.10": "a:gimp:gimp", "org.gimp.gimp-3.0": "a:gimp:gimp",
	"com.adobe.Reader": "a:adobe:acrobat_reader_dc", "com.adobe.Acrobat.Pro": "a:adobe:acrobat_dc",
	"com.apple.Safari": "a:apple:safari", "com.apple.dt.Xcode": "a:apple:xcode",
	"org.blenderfoundation.blender": "a:blender:blender", "org.filezilla-project.filezilla": "a:filezilla-project:filezilla_client",
	"org.keepassxc.keepassxc": "a:keepassxc:keepassxc", "org.qbittorrent.qBittorrent": "a:qbittorrent:qbittorrent",
	"org.audacityteam.audacity": "a:audacityteam:audacity", "com.obsproject.obs-studio": "a:obsproject:obs_studio",
}

var known = func() map[string]bool {
	m := map[string]bool{}
	for _, table := range []map[string]string{Formula, Bundle} {
		for _, v := range table {
			m[v] = true
		}
	}
	return m
}()

func Known(key string) bool { return known[key] }
