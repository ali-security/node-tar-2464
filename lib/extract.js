// give it a tarball and a path, and it'll dump the contents

module.exports = Extract

var tar = require("../tar.js")
  , fstream = require("fstream")
  , inherits = require("inherits")
  , path = require("path")
  , fs = require("fs")
  , stripAbsolutePath = require("./strip-absolute-path.js")

function Extract(opts) {
  if (!(this instanceof Extract)) return new Extract(opts)
  tar.Parse.apply(this)

  if (typeof opts !== "object") {
    opts = { path: opts }
  }

  // better to drop in cwd? seems more standard.
  opts.path = opts.path || path.resolve("node-tar-extract")
  opts.type = "Directory"
  opts.Directory = true

  // similar to --strip or --strip-components
  opts.strip = +opts.strip
  if (!opts.strip || opts.strip <= 0) opts.strip = 0

  this._fst = fstream.Writer(opts)

  this.pause()
  var me = this

  // Hardlinks in tarballs are relative to the root
  // of the tarball.  So, they need to be resolved against
  // the target directory in order to be created properly.
  me.on("entry", function (entry) {
    // if there's a "strip" argument, then strip off that many
    // path components.
    if (opts.strip) {
      var p = entry.path.split("/").slice(opts.strip).join("/")
      entry.path = entry.props.path = p
      if (entry.linkpath) {
        var lp = entry.linkpath.split("/").slice(opts.strip).join("/")
        entry.linkpath = entry.props.linkpath = lp
      }
    }

    // Normalize path separators for consistent checking
    var p = entry.path.replace(/\\/g, '/')

    // Check for path traversal attempts
    var parts = p.split('/')
    var isWindows = process.platform === 'win32'
    if (parts.indexOf('..') !== -1 || (isWindows && parts.length > 0 && /^[a-z]:\.\.$/i.test(parts[0]))) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path contains \'..\'', {
          entry: entry,
          path: p
        })
      }
      return // Skip this entry
    }

    // strip off the root
    // The updated stripAbsolutePath now also strips drive-local paths (e.g., c:foo)
    // even though they're not "absolute", to prevent path escape issues
    var s = stripAbsolutePath(p)
    if (s[0]) {
      entry.path = s[1]
      entry.props.path = s[1]
      if (entry.warn) {
        entry.warn('stripping ' + s[0] + ' from absolute path', p)
      }
    }

    // Resolve the absolute path for this entry
    var entryAbsolute = path.resolve(opts.path, entry.path)

    // Defense in depth: ensure the resolved path doesn't escape the extraction directory
    // This should have been prevented above, but provides additional safety
    var extractPath = path.resolve(opts.path)
    var normalizedExtract = extractPath.replace(/\\/g, '/')
    var normalizedEntry = entryAbsolute.replace(/\\/g, '/')

    if (normalizedEntry.indexOf(normalizedExtract + '/') !== 0 &&
      normalizedEntry !== normalizedExtract) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path escaped extraction target', {
          entry: entry,
          path: p,
          resolvedPath: normalizedEntry,
          cwd: normalizedExtract
        })
      }
      return // Skip this entry
    }

    // CVE-2018-20834 fix: Remove hardlinks before extracting File entries
    // to prevent overwriting the link target. fstream 1.0.2 doesn't handle this.
    if (entry.type === "File") {
      try {
        var fullPath = path.resolve(opts.path, entry.path)
        var stats = fs.statSync(fullPath)
        // If it's a hardlink (nlink > 1), remove it before fstream processes it
        // This prevents fstream from following the link and overwriting the target
        if (stats.nlink > 1) {
          fs.unlinkSync(fullPath)
        }
      } catch (err) {
        // File doesn't exist or other error - that's fine, continue
        // ENOENT means file doesn't exist, which is expected for new files
        if (err.code !== 'ENOENT') {
          // For other errors, log but don't fail - let fstream handle it
          if (entry.warn) {
            entry.warn('CVE-2018-20834: Could not check/remove hardlink', {
              path: entry.path,
              error: err.message
            })
          }
        }
      }
    }

    if (entry.type === "Link") {
      entry.linkpath = entry.props.linkpath =
        path.join(opts.path, path.join("/", entry.props.linkpath))
    }

    if (entry.type === "SymbolicLink") {
      var dn = path.dirname(entry.path) || ""
      var linkpath = entry.props.linkpath
      var target = path.resolve(opts.path, dn, linkpath)
      if (target.indexOf(opts.path) !== 0) {
        linkpath = path.join(opts.path, path.join("/", linkpath))
      }
      entry.linkpath = entry.props.linkpath = linkpath
    }
  })

  this._fst.on("ready", function () {
    me.pipe(me._fst, { end: false })
    me.resume()
  })

  this._fst.on('error', function (err) {
    me.emit('error', err)
  })

  this._fst.on('drain', function () {
    me.emit('drain')
  })

  // this._fst.on("end", function () {
  //   console.error("\nEEEE Extract End", me._fst.path)
  // })

  this._fst.on("close", function () {
    // console.error("\nEEEE Extract End", me._fst.path)
    me.emit("finish")
    me.emit("end")
    me.emit("close")
  })
}

inherits(Extract, tar.Parse)

Extract.prototype._streamEnd = function () {
  var me = this
  if (!me._ended || me._entry) me.error("unexpected eof")
  me._fst.end()
  // my .end() is coming later.
}
