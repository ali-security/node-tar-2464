// give it a tarball and a path, and it'll dump the contents

module.exports = Extract

var tar = require("../tar.js")
  , fstream = require("fstream")
  , inherits = require("inherits")
  , path = require("path")
  , stripAbsolutePath = require("./strip-absolute-path.js")

// Apply CVE-2018-20834 fix: Clobber a Link if it's in the way of a File
// This patch ensures that when extracting a File over an existing Link (hardlink),
// the link is properly removed before creating the file.
// Based on: https://github.com/npm/fstream/commit/6a77d2fa6e1462693cf8e46f930da96ec1b0bb22
// The fix changes the condition from:
//   if (currentType !== self.type)
// to:
//   if (currentType !== self.type || self.type === 'File' && current.nlink > 1)
if (fstream.Writer && fstream.Writer.prototype && fstream.Writer.prototype._stat) {
  var originalStat = fstream.Writer.prototype._stat
  fstream.Writer.prototype._stat = function(current) {
    var self = this
    var currentType = current && current.type
    
    // Apply the fix: if we're writing a File over a hardlink (nlink > 1),
    // ensure it gets clobbered even if types match.
    // The original condition (currentType !== self.type) might be false,
    // but with the fix we also clobber when (self.type === 'File' && current.nlink > 1).
    if (self.type === 'File' && current && current.nlink > 1) {
      // If the original condition would be false (types match), force it to be true
      // by temporarily changing current.type to trigger the clobber path
      if (currentType === self.type) {
        current.type = 'Link' // Force type mismatch to trigger clobber in original _stat
      }
    }
    
    var result = originalStat.call(self, current)
    
    // Restore original type if we modified it
    if (self.type === 'File' && current && current.nlink > 1 && currentType === self.type) {
      current.type = currentType
    }
    
    return result
  }
}

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
