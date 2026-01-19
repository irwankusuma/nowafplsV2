/**
 * nowafplsV2 - Burp Suite Extension for WAF Bypass
 *
 * Based on https://github.com/assetnote/nowafpls by Shubham Shah
 * Improved and maintained by Irwan Kusuma (https://www.linkedin.com/in/donesia)
 *
 * Montoya API version for BApp Store compliance.
 */
package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.Window;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.Deque;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NowafplsExtension implements BurpExtension {

    private MontoyaApi api;
    private boolean autoInjectEnabled = true;
    private int autoInjectKb = 128;

    // Rate limiting for alerts
    private final Map<String, Long> alertLast = new ConcurrentHashMap<>();

    // Deduplication for missing content-type logging (like Python version)
    private final Set<String> missingCtPaths = ConcurrentHashMap.newKeySet();
    private final Deque<String> missingCtOrder = new java.util.concurrent.ConcurrentLinkedDeque<>();
    private static final int MISSING_CT_LIMIT = 5000;

    // Random parameter prefixes for realistic junk data (synced with Python version)
    private static final String[] PARAM_PREFIXES = {
        "id", "user", "session", "token", "auth", "request", "data", "temp", "cache", "author",
        "authorID", "authorName", "authorityType", "authorize", "authorized", "authorizedkeys",
        "authors", "authorship", "authserver", "authtype", "auto", "autoaddfields", "autoadjust",
        "autoapprove", "autoassign", "autocomplete", "autodel", "autodeltime", "autoedge",
        "autoenable", "autofix", "autofixforcedest", "autofixforcesource", "autofocus", "autogroup",
        "autologin", "automatic", "autoplay", "autoptp", "autoredirect", "autorefresh", "autosave",
        "autoupdate", "avatar", "avatars", "backup", "backuparea", "backupbeforeupgrade",
        "backupcount", "backupnow", "backuptype", "backurl", "balance", "ban", "bandwidth",
        "banid", "banip", "bank", "banned", "bannedUser", "banner", "banreason", "bansubmit",
        "bantime", "bantype", "base", "base64", "basedn", "basemodule", "baseurl", "basic",
        "basket", "batch", "batchExtend", "batchID", "benchmark", "beta", "binary", "binding",
        "bindip", "bio", "birth", "birthDate", "birthdate", "birthday", "birthmonth", "birthplace",
        "birthyear", "bitrate", "bits", "blacklist", "block", "blockedafter", "blockedmacsurl",
        "blockeduntil", "blockid", "blocklabel", "blockpriv", "blocks", "blog", "blogbody",
        "blogid", "blogname", "blogs", "blogtags", "blogtitle", "blogusers", "board", "boardaccess",
        "boardid", "boardmod", "boardprofile", "boards", "boardseen", "boardtheme", "boardurl",
        "body", "bodytext", "bonus", "book", "bookings", "bookmark", "boolean", "border", "bottom",
        "bounce", "box", "branch", "brand", "breadcrumb", "bridge", "broadcast", "browse",
        "browser", "bucket", "buddies", "budget", "bug", "build", "bulk", "bulletin", "business",
        "businessName", "button", "buttons", "buy", "cache", "cacheable", "cached", "caching",
        "calendar", "calendarid", "callback", "campaign", "campaignid", "cancel", "cancelled",
        "captcha", "caption", "capture", "card", "cardno", "cardtype", "cart", "cartId", "case",
        "catalog", "catalogName", "catalogid", "categories", "category", "categoryID",
        "categoryName", "categoryid", "categoryname", "certificate", "challenge", "change",
        "changePass", "changeUserGroup", "changed", "changeit", "changepassword", "changes",
        "changestatus", "changeusername", "channel", "channelID", "channelName", "channelmode",
        "channels", "chapter", "charge", "chars", "charset", "chart", "chartSettings", "chartsize",
        "chat", "chatmsg", "chats", "check", "checkReshare", "checkShares", "checkbox", "checkboxes",
        "checked", "checkemail", "checkid", "checking", "checknum", "checkout", "checksum", "child",
        "children", "choice", "chosen", "chunk", "chunks", "cipher", "city", "claim", "class",
        "classOptions", "classification", "classname", "clean", "cleancache", "cleanup", "clear",
        "clearLog", "clearLogs", "clearSess", "clearcache", "cleared", "clearlogs", "clearquery",
        "clearsql", "cleartokens", "client", "clientId", "clientcookies", "clientid", "clipboard",
        "clone", "close", "closed", "closedate", "closenotice", "cluster", "code", "codeblock",
        "coded", "codes", "codetype", "coin", "collType", "collTypeID", "collTypeName", "collapse",
        "collation", "collection", "collectionfrom", "collectionto", "college", "colltype", "color",
        "colors", "colours", "cols", "column", "columnIndex", "columns", "columnsToDisplay",
        "combine", "combo", "command", "comment", "commentId", "commentaire", "commentid",
        "comments", "commenttext", "commit", "commits", "commonName", "communication", "community",
        "compact", "company", "compare", "complete", "completed", "component", "compose", "compress",
        "compression", "condition", "conditions", "config", "configfile", "configs", "configuration",
        "configure", "confirm", "confirmEmail", "confirmFinish", "confirmPassword", "confirmation",
        "confirmdelete", "confirmed", "confirmpassword", "conflict", "connect", "connection",
        "connectionType", "connections", "consent", "constraint", "consumer", "consumerKey",
        "consumerSecret", "contact", "contactEmail", "contactID", "contactId", "contactName",
        "contactid", "contactidlist", "contactname", "contacts", "container", "containerid",
        "contains", "content", "contentDesc", "contentPath", "contentTitle", "contentType",
        "contents", "contenttype", "contest", "context", "continue", "control", "controller",
        "controllers", "convert", "convertmode", "cookie", "cookielength", "cookiename", "cookies",
        "coord", "coords", "copied", "copy", "copyname", "copyright", "core", "correctcase", "cost",
        "count", "counter", "countonly", "country", "countryCode", "countryID", "countryName",
        "counts", "coupon", "couponamount", "couponcode", "course", "courseId", "courses", "cover",
        "coverage", "create", "createaccount", "createclass", "created", "createdb", "createdon",
        "createfolder", "createlist", "createmode", "createpages", "createuser", "createview",
        "credentials", "credit", "creditCardNumber", "creditCardType", "credits", "criteria",
        "current", "currentFolder", "currentFolderPath", "currentPage", "currentPassword",
        "currentday", "currentid", "cursor", "custom", "customFieldId", "customId",
        "customWhereClause", "customcss", "customer", "customerid", "customernumber", "customers",
        "customfield", "customized", "dashboard", "data", "dataLabel", "dataType", "database",
        "databasehost", "databaseloginname", "databaseloginpassword", "databasename", "databases",
        "datadir", "dataroot", "dataset", "datatype", "dataurl", "date", "dateEnd", "dateExpected",
        "dateFormat", "dateReceived", "dateStart", "datechange", "dateformat", "datefrom", "dates",
        "datestamp", "datetime", "dateto", "datetype", "day", "dayDelta", "dayname", "days",
        "deadline", "debug", "decode", "decoded", "decrypt", "default", "defaultValue", "defaults",
        "defaulttemplate", "degrees", "delay", "delete", "deleteAccount", "deleteCategory",
        "deleteImage", "deleteImages", "deleteIndex", "deleteList", "deletePrices", "deleteUser",
        "deleteUserGroup", "deleteUsers", "deleteall", "deletebookmarks", "deletecheck",
        "deletecomment", "deleted", "deletedir", "deleteevent", "deletefile", "deletefolder",
        "deleteid", "deleteip", "deletemeta", "deletepage", "deletepost", "deleterule",
        "deleteuser", "delimiter", "deliver", "deliveries", "delivery", "demo", "demoData", "denied",
        "deny", "department", "deposit", "depth", "desc", "descending", "descr", "descripcion",
        "description", "design", "dest", "destination", "destino", "detail", "details", "dev",
        "device", "deviceid", "dialog", "dictionary", "diff", "difficulty", "digest", "dim",
        "dimensions", "direct", "direction", "directmode", "director", "directory", "disable",
        "disabled", "disallow", "disapprove", "discard", "discipline", "discount", "disk",
        "diskspace", "dismiss", "display", "displayAllColumns", "displayName", "displayVisualization",
        "displayname", "distance", "distinct", "distribution", "diversity", "document", "documentID",
        "documentgroup", "documentroot", "domain", "domainname", "domains", "done", "donor",
        "download", "downloadIndex", "downloadbackup", "downloaded", "downloadid", "draft", "driver",
        "drop", "dropped", "droptables", "due", "duedate", "dummy", "dump", "duplicate", "duration",
        "dynamic", "edit", "editParts", "editUserGroup", "editUserGroupSubmit", "editable",
        "editaction", "edited", "editedon", "editfile", "editfilename", "editform", "editgroup",
        "editid", "editing", "edition", "editkey", "editor", "editprofile", "edituser", "editwidget",
        "education", "element", "elementId", "elementType", "elements", "email", "emailActivate",
        "emailAddress", "emailBody", "emailID", "emailId", "emailList", "emailToken", "emailaddress",
        "emailcomplete", "emailfrom", "emailnotif", "emails", "emailsubject", "emailto", "embed",
        "embedded", "emphasis", "empty", "enable", "enableReserve", "enabled", "encode", "encoded",
        "encoder", "encoding", "encrypt", "encrypted", "encryption", "end", "endDate", "enddate",
        "endday", "endmonth", "endpoint", "endport", "ends", "endtime", "endyear", "enforceHTTPS",
        "engine", "enhanced", "enquiry", "enroll", "entire", "entity", "entityID", "entityid",
        "entries", "entry", "entryID", "entryId", "entryPoint", "entryid", "env", "episode", "epoch",
        "error", "errorCode", "errormail", "errormsg", "errors", "errorstr", "event", "eventDate",
        "eventID", "eventId", "eventName", "eventTitle", "eventid", "eventname", "events", "exact",
        "example", "except", "exception", "excerpt", "exchange", "exclude", "excludedRecords", "exec",
        "execute", "executeForm", "existing", "exists", "exp", "expDate", "expDateMonth",
        "expDateYear", "expand", "expandAll", "expanded", "expertise", "expiration", "expirationDate",
        "expirationmonth", "expirationyear", "expire", "expires", "expiry", "explain", "export",
        "exportDetail", "exportFile", "exportFormat", "exportFrames", "exportImages", "exportMisc",
        "exportVideo", "extAction", "extMethod", "extend", "extended", "extension", "extensions",
        "extern", "external", "extra", "extractDir", "extras", "facebook", "facility", "fail",
        "failed", "failure", "fallback", "family", "familyName", "fast", "favicon", "favicons",
        "favorites", "favourite", "fax", "feature", "featured", "features", "fee", "feed", "feedId",
        "feedback", "feeds", "feedurl", "fetch", "field", "fieldCounter", "fieldEnc", "fieldId",
        "fieldName", "fieldSep", "fieldType", "fieldValue", "fieldid", "fieldkey", "fieldlabel",
        "fieldname", "fields", "fieldtype", "file", "fileContent", "fileDataName", "fileDesc",
        "fileDir", "fileEdit", "fileExistsAction", "fileFormat", "fileID", "fileLength", "fileName",
        "fileOffset", "fileTitle", "fileType", "fileURL", "filecontent", "filecontents", "filecount",
        "filecreate", "fileext", "fileextensions", "fileframe", "filefrom", "fileid", "filelist",
        "filename", "filenamepattern", "filenew", "fileoffset", "fileold", "filepath", "fileperm",
        "files", "filesend", "filesize", "fileto", "filetosave", "filetotal", "filetype",
        "filetypelist", "fileurl", "fill", "filled", "filter", "filterAlert", "filterCategory",
        "filterName", "filterText", "filterdescriptions", "filters", "filtertext", "filtertype",
        "find", "findString", "findid", "finds", "finish", "finishID", "finished", "first",
        "firstName", "firstday", "firstname", "fix", "fixErrors", "flag", "flags", "flash",
        "flashtype", "flip", "floating", "floor", "flow", "flush", "flushcache", "focus", "folder",
        "folderID", "folderId", "folderid", "foldername", "folderpath", "folders", "follow",
        "following", "followup", "font", "fontSize", "fontcolor", "fontsize", "footer", "force",
        "forceFormat", "forceIcon", "forceRefresh", "foreground", "foreign", "foreignDb",
        "foreignTable", "forever", "forgot", "forgotPassword", "form", "formAutosave", "formId",
        "formName", "formSubmit", "format", "formats", "formdata", "formfactor", "formid", "formname",
        "forum", "forumid", "forums", "forward", "forwarding", "fragment", "frame", "framed",
        "frames", "free", "frequency", "frequencyID", "frequencyName", "fresh", "friend", "friends",
        "from", "fromAddress", "fromdate", "fromemail", "fromname", "fromsearch", "front", "frontend",
        "frontpage", "full", "fullfolder", "fullname", "fullsite", "fulltext", "func", "funcs",
        "function", "gallery", "game", "gameID", "gameid", "gateway", "gender", "general",
        "generalgroup", "generate", "generateKeypair", "generated", "generatekey", "generic", "genre",
        "gift", "github", "global", "goal", "gold", "google", "googleplus", "goto", "grade", "grant",
        "granted", "grants", "granularity", "graph", "graphid", "graphtype", "grid", "group",
        "groupCounter", "groupID", "groupIDs", "groupId", "groupName", "groupby", "groupdel",
        "groupdesc", "grouped", "groupfilter", "groupid", "groupname", "groupreason", "groups",
        "grouptype", "guest", "guestname", "guid", "handle", "handler", "hash", "hashed", "hashkey",
        "having", "head", "header", "headerimage", "headers", "heading", "headline", "health",
        "height", "help", "hidden", "hide", "hideNavItem", "highlight", "history", "hit", "home",
        "homepage", "hook", "host", "hostName", "hostid", "hostname", "hosts", "hour", "hours",
        "html", "htmlemail", "https", "icon", "id", "id1", "id2", "identifier", "identity", "idx",
        "ignore", "ignoreTV", "ignored", "image", "imageThumbID", "imageUrl", "imagedetails",
        "imagefile", "imageid", "imagename", "images", "imagesize", "immediate", "impersonate",
        "import", "importFile", "importType", "importance", "important", "importer", "importfile",
        "importid", "importmethod", "importonly", "inactive", "include", "indent", "index", "indexes",
        "industry", "info", "inherit", "inheritperm", "init", "initdb", "initial", "initialise",
        "initialtext", "inline", "input", "inputSearchVal", "inputSize", "inputid", "insert",
        "insertonly", "insertonlybutton", "inside", "install", "installGoingOn", "installdata",
        "installed", "installmode", "installpath", "installstep", "instance", "instanceId",
        "institution", "interest", "interests", "interface", "interfaces", "interval", "intro",
        "invalid", "invalidate", "inventory", "inventoryCode", "inverse", "invitation", "invite",
        "invitecode", "invited", "invitepage", "invites", "invoice", "invoiceId", "invoiceid",
        "ip", "ipaddr", "ipaddress", "isAjax", "isDev", "isDuplicate", "isPending", "isPersonal",
        "isSwitch", "isactive", "iscomment", "iscustomreport", "isdescending", "isenabled", "isbn",
        "ispublic", "issue", "issues", "item", "itemAction", "itemCode", "itemCollID", "itemID",
        "itemId", "itemName", "itemShares", "itemSite", "itemSource", "itemSourceName", "itemStatus",
        "itemStatusID", "itemType", "itemcount", "itemid", "itemkey", "itemname", "items", "job",
        "join", "joindate", "joined", "joingroup", "json", "key", "key1", "key2", "keydata", "keyid",
        "keylen", "keyname", "keys", "keystring", "keytype", "keyword", "keywords", "kind", "label",
        "labelDesc", "labelName", "labels", "lang", "langCode", "langID", "langName", "langname",
        "langs", "language", "languageID", "languagePrefix", "languages", "last", "lastActive",
        "lastID", "lastName", "lastQueryStr", "lastactive", "lastid", "lastmodified", "lastname",
        "lasturl", "latest", "latitude", "layer", "layers", "layout", "layoutType", "lead",
        "leadsource", "leave", "lecture", "left", "legend", "length", "letter", "level", "levels",
        "lib", "library", "license", "lifetime", "like", "liked", "limit", "limitTypes", "limite",
        "limitless", "limitpage", "line", "lineid", "lines", "link", "linkname", "links", "linktype",
        "linkurl", "list", "listId", "listInfo", "listItem", "listPrice", "listShow", "listSubmitted",
        "listarea", "listdirectory", "listid", "listing", "listmode", "listname", "listorder",
        "listprice", "lists", "live", "liveupdate", "load", "loader", "loan", "loanID", "loanLimit",
        "loanPeriode", "loanSessionID", "loanStatus", "local", "locale", "localfile", "localize",
        "localized", "location", "locationID", "locationName", "locationid", "locations", "lock",
        "locked", "lockid", "log", "logFile", "logMeIn", "logType", "logable", "logall", "logged",
        "loggedin", "loggedout", "logging", "logic", "logid", "login", "loginautocomplete",
        "loginemail", "loginguest", "loginmessage", "loginname", "loglevel", "logo", "logoff",
        "logout", "logoutRequest", "logoutid", "logs", "logtype", "long", "longitude", "longurl",
        "lookup", "loop", "lowercase", "mail", "mailAuth", "mailMethod", "mailSubject", "mailbody",
        "mailbodyid", "mailbox", "mailcontent", "mailid", "mailing", "mailsent", "mailsub", "mailto",
        "mailtxt", "main", "mainGenre", "mainmessage", "maint", "maintenance", "maintitle", "make",
        "makedir", "makedoc", "manage", "manager", "managerlanguage", "mandatory", "manual",
        "manufacturer", "map", "mapping", "mark", "markdefault", "markdown", "marked", "marker",
        "markread", "mask", "mass", "master", "match", "matchcase", "matchname", "matchtype",
        "matchuser", "matchword", "max", "maxPlotLimit", "maxResults", "maxUploadSize",
        "maxZipInputSize", "maxage", "maxcrop", "maxdays", "maxentries", "maximumstates", "maxproc",
        "maxrejects", "maxstore", "maxtemp", "maxtime", "maxtry", "maxwidth", "media", "mediaid",
        "mediatype", "member", "memberAddress", "memberEmail", "memberFax", "memberID", "memberName",
        "memberNotes", "memberPIN", "memberPassWord", "memberPasswd", "memberPhone", "memberPostal",
        "memberTypeID", "memberTypeName", "membergroups", "membername", "members", "memo", "memory",
        "memtype", "menu", "menuHashes", "menuid", "menuindex", "menus", "menutitle", "merge",
        "mergefile", "message", "messageMultiplier", "messagebody", "messageid", "messages",
        "messagesubject", "meta", "metadata", "method", "metric", "metrics", "migrate", "mime",
        "mimetype", "mimetypes", "min", "minCss", "minJs", "minViewability", "minage", "mini",
        "minimum", "minor", "minus", "minute", "minuteDelta", "minutes", "mirror", "misc", "missing",
        "mode", "modeextension", "modeid", "model", "modelId", "moderate", "moderator", "moderators",
        "modified", "modifiedSince", "modifier", "modify", "module", "moduleDesc", "moduleId",
        "moduleName", "modulePath", "moduleType", "moduleguid", "moduleid", "modulename",
        "moduleorder", "modules", "moduletype", "money", "monitor", "monitorconfig", "month",
        "monthnum", "months", "mood", "more", "mount", "mountPoint", "mountType", "move", "moved",
        "movedown", "movefile", "moveto", "moveup", "movie", "msg", "msgfield", "msgid", "msgs",
        "msgtype", "multi", "multifieldid", "multifieldname", "multiple", "multiplier", "music",
        "mute", "name", "namelist", "names", "namespace", "nav", "navigation", "nested", "network",
        "networkwide", "new", "newControl", "newDir", "newDirectory", "newDueDate", "newFileName",
        "newGame", "newGroup", "newHeight", "newLoanDate", "newMonitor", "newName", "newPass",
        "newPassword", "newPath", "newProject", "newSite", "newText", "newUser", "newValue",
        "newWidth", "newWindow", "newaccount", "newcat", "newcategory", "newcode", "newcontent",
        "newdb", "newdir", "newdirectory", "newemail", "newer", "newfile", "newfolder", "newgroup",
        "newgroupname", "newid", "newids", "newlang", "newmessage", "newname", "newnick", "newowner",
        "newpage", "newpass", "newpassword", "newpath", "newpref", "newprefix", "newrule", "news",
        "newscan", "newsid", "newsletter", "newstatus", "newtag", "newtemplate", "newtext",
        "newtheme", "newtime", "newtitle", "newtype", "newuser", "newuseremail", "newusergroup",
        "newusername", "newvalue", "newver", "newwin", "next", "nextPage", "nextid", "nick",
        "nickname", "node", "nodeid", "noedit", "noexpand", "nogrants", "noheader", "nohtml",
        "nolang", "nolimit", "nolog", "none", "noquery", "noredir", "noredirect", "noreload",
        "nosync", "not", "notactivated", "notdeleted", "note", "noteid", "notes", "notice", "notices",
        "notification", "notificationCode", "notificationType", "notifications", "notify", "noupdate",
        "nowarn", "null", "num", "numExtended", "number", "numberposts", "numbers", "numlabel",
        "oauth", "object", "objectIDs", "objects", "occupation", "off", "offline", "offset", "ok",
        "old", "oldEmail", "oldMountPoint", "oldPassword", "oldaction", "olddir", "oldemail",
        "older", "oldfilename", "oldform", "oldname", "oldpass", "oldpassword", "oldtime",
        "oldusername", "on", "online", "onlyfind", "onlyforuser", "open", "opened", "opener",
        "openid", "openings", "operation", "operations", "operator", "opt", "optimization",
        "optimize", "optimizer", "optin", "option", "options", "or", "order", "orderBy",
        "orderByColumn", "orderId", "orderNo", "orderType", "orderby", "orderbydate", "orderdir",
        "orderid", "ordering", "orders", "org", "organization", "organizationName", "orientation",
        "origin", "original", "origname", "os", "other", "out", "outbox", "output", "overdue",
        "override", "overrideID", "overwrite", "owner", "pack", "package", "packageName", "padding",
        "page", "pageID", "pageId", "pageOwner", "pageSize", "pageTitle", "pageType", "pageborder",
        "paged", "pageid", "pagename", "pageno", "pagenow", "pagenum", "pagenumber", "pages",
        "pagesize", "pagestart", "pagestyle", "pagetitle", "pagination", "paid", "palette", "panel",
        "paper", "param", "param1", "param2", "parameter", "parameters", "params", "parent",
        "parentID", "parentId", "parentfieldid", "parentid", "parenttab", "partial", "partition",
        "partner", "pass", "passWord", "passenger", "passkey", "passlength", "passphrase", "passwd",
        "password", "passwordConfirm", "passwordconfirm", "passwordkey", "passwords", "paste",
        "patch", "path", "paths", "pattern", "pause", "pay", "payload", "payment", "paymentAmount",
        "paymentData", "paymentId", "paymentStatus", "paymentType", "payments", "pending", "perPage",
        "percent", "perform", "period", "periodidx", "periodo", "perm", "permStatus", "permalink",
        "permanent", "permerror", "permission", "permissions", "perms", "perpage", "persist",
        "persistent", "person", "personId", "personal", "personality", "phone", "phoneNr",
        "phonenumber", "photo", "photoid", "phrase", "pic", "pick", "pics", "picture", "pin",
        "pinned", "place", "placeID", "placeName", "placement", "plain", "plaintext", "plan",
        "platform", "play", "player", "playlist", "plugin", "plugins", "point", "pointer", "points",
        "policies", "poll", "pollOptions", "pollQuestion", "pollid", "pollvote", "pool", "poolname",
        "pools", "popup", "popuptitle", "popuptype", "popupurl", "port", "position", "post",
        "postData", "postId", "postRedirect", "postafterlogin", "postal", "postback", "postcode",
        "posted", "postedText", "poster", "postfrom", "postgroup", "postgroups", "postid", "posts",
        "postsperpage", "posttext", "postto", "posttype", "power", "pre", "predefined", "pref",
        "preference", "prefetch", "prefetchkey", "prefix", "prepare", "prepopulate", "prereq",
        "presence", "preset", "press", "pretty", "prev", "preview", "previewed", "previewwrite",
        "previous", "prevpage", "price", "priceCurrency", "prices", "primary", "primarymodule",
        "principal", "print", "printer", "printview", "priority", "privacy", "private", "privatekey",
        "privileges", "pro", "probability", "problem", "procedure", "proceed", "process", "processed",
        "processing", "processlist", "processlogin", "product", "productDescription", "productcode",
        "productid", "productlist", "productname", "products", "producttype", "profile", "profileId",
        "profiler", "profiles", "profiling", "program", "progress", "progresskey", "project",
        "projectID", "projectid", "projection", "projects", "promote", "properties", "property",
        "protect", "protection", "proto", "protocol", "provider", "province", "proxy", "proxyhost",
        "proxypass", "proxypassword", "proxyport", "proxypwd", "proxyurl", "proxyuser",
        "proxyusername", "prune", "pruningOptions", "pseudo", "pub", "pubdate", "pubkey", "public",
        "publicUpload", "publickey", "publish", "published", "publisher", "publisherID",
        "publisherName", "purchaseid", "purchaseorderid", "purge", "purgedb", "purpose", "push",
        "qty", "quality", "quantity", "quantityBackup", "query", "queryPart", "queryString",
        "queryType", "querysql", "querytype", "quest", "question", "questionid", "questions", "queue",
        "quick", "quickReturnID", "quicklogin", "quickmanager", "quickmod", "quiet", "quota", "quote",
        "quoteid", "race", "radio", "radiobutton", "radius", "rand", "randkey", "random", "range",
        "rank", "ranking", "rate", "rating", "ratings", "ratio", "raw", "rawAuthMessage", "rawfilter",
        "read", "reading", "readme", "readonly", "ready", "realName", "realm", "realname", "realpath",
        "reason", "reasontype", "reauth", "reauthenticate", "rebuild", "recache", "recapBy",
        "recaptcha", "receipt", "receiver", "recent", "recipient", "recipientAmount",
        "recipientCurrency", "recipients", "recommend", "reconstruct", "record", "recordID",
        "recordNum", "recordOffset", "recordSep", "recordType", "recordcount", "recordid", "records",
        "recordsArray", "recover", "recovered", "recoveryPassword", "recreate", "recsEachPage",
        "recurrence", "recurring", "recurringtype", "recurse", "recursive", "redir", "redirect",
        "redirectUri", "redirection", "redirectto", "redirurl", "ref", "reference", "referer",
        "referer2", "referid", "referral", "referredby", "referrer", "refid", "refresh",
        "refreshinterval", "refund", "refurl", "refuse", "reg", "regDate", "regSubmit", "regcountry",
        "regdomain", "regenerate", "regex", "regexp", "regid", "reginput", "region", "register",
        "registered", "registration", "registre", "reglocation", "regname", "regtype", "regularity",
        "regval", "reinstall", "rel", "related", "relatedmodule", "relation", "relations",
        "relationship", "relationships", "relative", "relay", "release", "releasedate", "relevance",
        "reload", "reloadfilter", "rem", "remark", "remarks", "remember", "rememberMe", "rememberme",
        "reminder", "remote", "remotefile", "remoteip", "remotekey", "remoteserver", "remove",
        "removeAll", "removeFines", "removeID", "removeOldVisits", "removeVariables", "removeall",
        "removefields", "removeheader", "removeid", "removesess", "removewidget", "rename",
        "renameext", "renamefile", "renamefileto", "renamefolder", "render", "renderfields",
        "renderforms", "renderimages", "renderlinks", "reopen", "reorder", "repair", "repass",
        "repassword", "repeat", "repeatMonth", "repeatable", "replace", "replaceWith", "replayMode",
        "replies", "reply", "replyto", "replytocom", "repo", "repopulate", "report",
        "reportContentType", "reportType", "reportView", "reportfun", "reportid", "reportname",
        "reports", "reportsent", "repositoryurl", "req", "reqFor", "reqType", "reqid", "request",
        "requestKey", "requestcompression", "requestid", "requests", "requireAgreement", "required",
        "requiredData", "res", "rescanerrors", "resend", "resent", "reserveAlert", "reserveID",
        "reserveItemID", "reserveLimit", "reserved", "reset", "resetPassword", "resetVoteCount",
        "resetheader", "resetkey", "resetlog", "resetlogs", "resetpass", "resetpasskey",
        "resetpassword", "resettext", "resetwidgets", "reshares", "residence", "resize", "resizefile",
        "resizetype", "resolution", "resolve", "resource", "resourcefile", "resources", "response",
        "responsecompression", "responsive", "restart", "restock", "restore", "restorearea",
        "restorefile", "restrict", "resubmit", "result", "resultXML", "resultid", "resultmatch",
        "results", "resume", "resync", "ret", "retries", "retry", "return", "returnID", "returnURL",
        "returnUrl", "returnaction", "returnpage", "returnsession", "returnto", "returnurl", "rev",
        "reveal", "reverse", "reverseacct", "revert", "review", "revision", "revoke", "revokeall",
        "rewrite", "right", "rights", "role", "roleid", "rolename", "roles", "rollback", "room",
        "root", "rootpath", "rotate", "rotatefile", "round", "route", "routeid", "routes", "routines",
        "row", "rowId", "rowid", "rownum", "rownumber", "rows", "rowspage", "rss", "rssfeed",
        "rssmaxitems", "rssurl", "rule", "ruledef", "ruledefgroup", "ruleid", "rules", "ruletype",
        "run", "runQuery", "runState", "runcmd", "runid", "runsnippet", "runtests", "safe", "safecss",
        "safefile", "saleprice", "salesrank", "salt", "salutation", "same", "sample", "sampledata",
        "sandbox", "save", "saveData", "saveField", "saveLogs", "saveNback", "saveNclose",
        "saveNcreate", "saveNedit", "savePath", "saveToFile", "saveandnext", "saveasdraft",
        "saveauthors", "saveconf", "saved", "savedraft", "savefile", "savefilename", "savefilenameurl",
        "savefolder", "savefolderurl", "savegroup", "savehostid", "saveid", "savemode", "savemsg",
        "saveoptions", "savesettings", "savetest", "scale", "scalepoints", "scalingup", "scan",
        "scenario", "scene", "schedule", "scheduled", "schema", "scheme", "school", "scope", "score",
        "scores", "screen", "script", "scripts", "scrollto", "search", "searchClause",
        "searchClause2", "searchField", "searchId", "searchKey", "searchName", "searchOper",
        "searchQuery", "searchString", "searchTerm", "searchText", "searchType", "searchUsername",
        "searchable", "searchaction", "searchbox", "searchby", "searchfield", "searchid", "searchin",
        "searchip", "searchlabel", "searchstring", "searchterm", "searchtext", "searchtype",
        "searchuser", "searchval", "season", "sec", "second", "secret", "secretKey", "secs", "sect",
        "section", "sectionid", "sections", "security", "seed", "segment", "sel", "selCountry",
        "select", "selectAmount", "selectall", "selectcategory", "selected", "selectedDoc",
        "selectedTable", "selectedmodule", "selection", "selectlist", "selectop", "selector",
        "selectvalues", "send", "sendTo", "sendactivation", "sendemail"
    };

    private static final Random random = new Random();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("nowafplsV2 (https://www.linkedin.com/in/donesia)");

        // Load settings
        loadSettings();

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(new NowafplsContextMenu());

        // Register HTTP handler for auto-inject
        api.http().registerHttpHandler(new NowafplsHttpHandler());

        // Register unload handler
        api.extension().registerUnloadingHandler(this::extensionUnloaded);

        api.logging().logToOutput("[nowafplsV2] Extension loaded successfully.");
        api.logging().logToOutput("[nowafplsV2] Auto-inject: " + (autoInjectEnabled ? "ON" : "OFF") + ", Size: " + autoInjectKb + " KB");
    }

    private void loadSettings() {
        String enabled = api.persistence().extensionData().getString("auto_inject_enabled");
        if (enabled != null) {
            autoInjectEnabled = enabled.equalsIgnoreCase("true");
        }

        String sizeStr = api.persistence().extensionData().getString("auto_inject_kb");
        if (sizeStr != null) {
            try {
                autoInjectKb = Integer.parseInt(sizeStr);
            } catch (NumberFormatException ignored) {}
        }
    }

    private void saveSettings() {
        api.persistence().extensionData().setString("auto_inject_enabled", autoInjectEnabled ? "true" : "false");
        api.persistence().extensionData().setString("auto_inject_kb", String.valueOf(autoInjectKb));
    }

    private void extensionUnloaded() {
        alertLast.clear();
        missingCtPaths.clear();
        missingCtOrder.clear();
        api.logging().logToOutput("[nowafplsV2] Extension unloaded. Resources cleaned up.");
    }

    // ==================== Error Handling (like Python version) ====================

    private void alertError(String context, boolean rateLimit) {
        try {
            long now = System.currentTimeMillis();
            if (rateLimit) {
                Long last = alertLast.get(context);
                if (last != null && (now - last) < 60000) { // 60 seconds rate limit
                    return;
                }
                alertLast.put(context, now);
            }
            api.logging().raiseInfoEvent("[nowafplsV2] Error in " + context + ". See Extender output.");
        } catch (Exception ignored) {}
    }

    private void maybeLogMissingContentType(HttpRequest request, String method, String url) {
        // Check if request has body
        if (request.body() == null || request.body().length() == 0) {
            return;
        }

        String contentTypeHeader = getContentTypeHeader(request);
        boolean hasHeader = contentTypeHeader != null && !contentTypeHeader.isEmpty();

        if (hasHeader) {
            String rawContentType = contentTypeHeader.split(";")[0].trim().toLowerCase();
            if (isSupportedContentType(rawContentType)) {
                return;
            }
        }

        String key = method + " " + url;
        if (missingCtPaths.contains(key)) {
            return;
        }

        missingCtPaths.add(key);
        missingCtOrder.addLast(key);

        // Evict old entries if over limit
        while (missingCtPaths.size() > MISSING_CT_LIMIT) {
            String oldKey = missingCtOrder.pollFirst();
            if (oldKey != null) {
                missingCtPaths.remove(oldKey);
            }
        }

        String displayContentType;
        if (!hasHeader) {
            displayContentType = "<missing>";
        } else if (contentTypeHeader == null || contentTypeHeader.isEmpty()) {
            displayContentType = "<unknown>";
        } else {
            displayContentType = contentTypeHeader.split(";")[0].trim();
        }

        api.logging().logToOutput("[nowafplsV2] Unsupported or missing Content-Type with body: " + method + " " + url + " (Content-Type: " + displayContentType + ")");
    }

    private boolean isSupportedContentType(String rawContentType) {
        return rawContentType.contains("application/x-www-form-urlencoded") ||
               rawContentType.contains("application/json") ||
               rawContentType.contains("text/json") ||
               rawContentType.contains("application/xml") ||
               rawContentType.contains("text/xml") ||
               rawContentType.contains("multipart/form-data") ||
               rawContentType.contains("text/plain") ||
               rawContentType.contains("application/graphql") ||
               rawContentType.contains("text/graphql") ||
               rawContentType.contains("application/yaml") ||
               rawContentType.contains("text/yaml") ||
               rawContentType.contains("text/csv") ||
               rawContentType.contains("application/csv") ||
               rawContentType.contains("application/ndjson") ||
               rawContentType.contains("application/jsonl") ||
               rawContentType.contains("application/json-lines") ||
               rawContentType.contains("application/jsonlines") ||
               rawContentType.contains("application/x-ndjson") ||
               rawContentType.contains("application/x-jsonl") ||
               rawContentType.contains("application/x-json-lines") ||
               rawContentType.contains("application/x-jsonlines") ||
               rawContentType.contains("text/ndjson") ||
               rawContentType.contains("text/jsonl") ||
               rawContentType.contains("text/json-lines") ||
               rawContentType.contains("text/jsonlines");
    }

    // ==================== Context Menu ====================

    private class NowafplsContextMenu implements ContextMenuItemsProvider {

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menuItems = new ArrayList<>();

            // Skip Intruder payload positions context (like Python version)
            InvocationType invocationType = event.invocationType();
            boolean isIntruderPayloadPositions = invocationType == InvocationType.INTRUDER_PAYLOAD_POSITIONS;

            // Skip Intruder message editor request (like Python version)
            boolean isIntruderMessageEditor = event.isFromTool(ToolType.INTRUDER) &&
                invocationType == InvocationType.MESSAGE_EDITOR_REQUEST;

            // Insert Junk Data Size - only for message editor with request, excluding Intruder contexts
            if (!isIntruderPayloadPositions && !isIntruderMessageEditor) {
                if (event.messageEditorRequestResponse().isPresent()) {
                    MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
                    if (editor.requestResponse().request() != null) {
                        JMenuItem insertItem = new JMenuItem("Insert Junk Data Size");
                        insertItem.addActionListener(e -> insertJunkData(editor));
                        menuItems.add(insertItem);
                    }
                } else if (!event.selectedRequestResponses().isEmpty()) {
                    JMenuItem insertItem = new JMenuItem("Insert Junk Data Size");
                    insertItem.addActionListener(e -> insertJunkDataFromSelection(event.selectedRequestResponses()));
                    menuItems.add(insertItem);
                }
            }

            // Auto-inject toggle (always show)
            String toggleLabel = "Auto-Inject (Scanner/DAST): " + (autoInjectEnabled ? "ON" : "OFF");
            JMenuItem toggleItem = new JMenuItem(toggleLabel);
            toggleItem.addActionListener(e -> toggleAutoInject());
            menuItems.add(toggleItem);

            // Set auto-inject size (always show)
            String sizeLabel = "Set Auto-Inject Size (KB) [" + autoInjectKb + "]";
            JMenuItem sizeItem = new JMenuItem(sizeLabel);
            sizeItem.addActionListener(e -> setAutoInjectSize());
            menuItems.add(sizeItem);

            return menuItems;
        }
    }

    private void toggleAutoInject() {
        autoInjectEnabled = !autoInjectEnabled;
        saveSettings();
        api.logging().logToOutput("[nowafplsV2] Auto-inject: " + (autoInjectEnabled ? "ON" : "OFF"));
    }

    private void setAutoInjectSize() {
        String input = JOptionPane.showInputDialog(null, "Auto-inject size (KB):", String.valueOf(autoInjectKb));
        if (input == null) return;

        try {
            int size = Integer.parseInt(input.trim());
            if (size <= 0) throw new NumberFormatException();
            autoInjectKb = size;
            saveSettings();
            api.logging().logToOutput("[nowafplsV2] Auto-inject size set to: " + autoInjectKb + " KB");
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(null, "Please enter a positive integer (KB).");
        }
    }

    private void insertJunkData(MessageEditorHttpRequestResponse editor) {
        try {
            HttpRequest request = editor.requestResponse().request();
            int sizeBytes = showSizeDialog();
            if (sizeBytes <= 0) return;

            // Log unsupported content types (like Python version)
            maybeLogMissingContentType(request, request.method(), request.url());

            HttpRequest newRequest = injectJunkIntoRequest(request, sizeBytes);
            if (newRequest != null) {
                editor.setRequest(newRequest);
                api.logging().logToOutput("[nowafplsV2] Junk data inserted: " + sizeBytes + " bytes");
            } else {
                JOptionPane.showMessageDialog(null, "Unsupported content type for junk injection.");
            }
        } catch (Exception e) {
            api.logging().logToError("[nowafplsV2] Error inserting junk: " + e.getMessage());
            alertError("insertJunkData", false);
            JOptionPane.showMessageDialog(null, "Error injecting junk data. Check Burp logs.");
        }
    }

    private void insertJunkDataFromSelection(List<HttpRequestResponse> selections) {
        if (selections.isEmpty()) return;

        try {
            int sizeBytes = showSizeDialog();
            if (sizeBytes <= 0) return;

            HttpRequest request = selections.get(0).request();

            // Log unsupported content types (like Python version)
            maybeLogMissingContentType(request, request.method(), request.url());

            HttpRequest newRequest = injectJunkIntoRequest(request, sizeBytes);

            if (newRequest != null) {
                api.logging().logToOutput("[nowafplsV2] Junk data prepared: " + sizeBytes + " bytes");
                // Note: Cannot modify selection directly, log success
            } else {
                JOptionPane.showMessageDialog(null, "Unsupported content type for junk injection.");
            }
        } catch (Exception e) {
            api.logging().logToError("[nowafplsV2] Error: " + e.getMessage());
            alertError("insertJunkDataFromSelection", false);
        }
    }

    private int showSizeDialog() {
        String[] options = {"8 KB", "16 KB", "32 KB", "64 KB", "128 KB", "150 KB", "1024 KB", "Custom"};

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JComboBox<String> dropdown = new JComboBox<>(options);
        JTextField customField = new JTextField(10);
        JLabel customLabel = new JLabel("Custom size (bytes):");

        customField.setVisible(false);
        customLabel.setVisible(false);

        dropdown.addActionListener(e -> {
            boolean isCustom = "Custom".equals(dropdown.getSelectedItem());
            customLabel.setVisible(isCustom);
            customField.setVisible(isCustom);
            Window window = SwingUtilities.getWindowAncestor(panel);
            if (window != null) {
                window.pack();
            }
        });

        panel.add(dropdown);
        panel.add(customLabel);
        panel.add(customField);

        int result = JOptionPane.showConfirmDialog(null, panel, "Select Junk Data Size",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result != JOptionPane.OK_OPTION) return -1;

        String selected = (String) dropdown.getSelectedItem();
        if ("Custom".equals(selected)) {
            try {
                int customSize = Integer.parseInt(customField.getText().trim());
                if (customSize <= 0) throw new NumberFormatException();
                return customSize;
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "Please enter a valid positive number.");
                return -1;
            }
        } else {
            return Integer.parseInt(selected.split(" ")[0]) * 1024;
        }
    }

    // ==================== HTTP Handler ====================

    private class NowafplsHttpHandler implements HttpHandler {

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            if (!autoInjectEnabled) {
                return RequestToBeSentAction.continueWith(request);
            }

            // Support Scanner (Pro/Community) and Extensions (DAST)
            ToolType toolType = request.toolSource().toolType();
            if (toolType != ToolType.SCANNER && toolType != ToolType.EXTENSIONS) {
                return RequestToBeSentAction.continueWith(request);
            }

            // Check if request has body
            if (request.body() == null || request.body().length() == 0) {
                return RequestToBeSentAction.continueWith(request);
            }

            // Check for chunked encoding
            if (isChunked(request)) {
                return RequestToBeSentAction.continueWith(request);
            }

            // Log unsupported content types (like Python version)
            maybeLogMissingContentType(request, request.method(), request.url());

            try {
                int sizeBytes = autoInjectKb * 1024;
                HttpRequest newRequest = injectJunkIntoRequest(request, sizeBytes);

                if (newRequest != null) {
                    return RequestToBeSentAction.continueWith(newRequest, request.annotations().withNotes("Junk Data"));
                }
            } catch (Exception e) {
                api.logging().logToError("[nowafplsV2] Auto-inject error: " + e.getMessage());
                alertError("processHttpMessage", true);
            }

            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            return ResponseReceivedAction.continueWith(response);
        }
    }

    // ==================== Junk Injection Logic ====================

    private HttpRequest injectJunkIntoRequest(HttpRequest request, int sizeBytes) {
        String contentTypeHeader = getContentTypeHeader(request);
        if (contentTypeHeader == null || contentTypeHeader.isEmpty()) {
            return null;
        }

        String rawContentType = contentTypeHeader.split(";")[0].trim().toLowerCase();
        String body = request.bodyToString();

        String newBody = null;

        switch (rawContentType) {
            case "application/x-www-form-urlencoded":
                newBody = injectUrlEncoded(body, sizeBytes);
                break;
            case "application/json":
                newBody = injectJson(body, sizeBytes);
                break;
            case "application/xml":
            case "text/xml":
                newBody = injectXml(body, sizeBytes);
                break;
            case "multipart/form-data":
                String boundary = extractBoundary(contentTypeHeader);
                if (boundary != null) {
                    newBody = injectMultipart(body, boundary, sizeBytes);
                }
                break;
            case "text/plain":
                newBody = injectTextPlain(body, sizeBytes);
                break;
            case "application/graphql":
            case "application/x-graphql":
            case "text/graphql":
                newBody = injectLineComment(body, sizeBytes, "# ");
                break;
            case "application/yaml":
            case "application/x-yaml":
            case "text/yaml":
            case "text/x-yaml":
                newBody = injectLineComment(body, sizeBytes, "# ");
                break;
            case "application/ndjson":
            case "application/x-ndjson":
            case "application/jsonlines":
            case "application/x-jsonlines":
            case "application/jsonl":
            case "application/x-jsonl":
            case "text/ndjson":
            case "text/x-ndjson":
            case "text/jsonlines":
            case "text/x-jsonlines":
            case "text/jsonl":
            case "text/x-jsonl":
                newBody = injectJsonLines(body, sizeBytes);
                break;
            case "text/csv":
            case "application/csv":
                newBody = injectCsv(body, sizeBytes);
                break;
            default:
                return null;
        }

        if (newBody == null) return null;

        return request.withBody(newBody);
    }

    private String getContentTypeHeader(HttpRequest request) {
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                .map(h -> h.value())
                .findFirst()
                .orElse(null);
    }

    private boolean isChunked(HttpRequest request) {
        return request.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase("Transfer-Encoding")
                        && h.value().toLowerCase().contains("chunked"));
    }

    private String extractBoundary(String contentType) {
        Pattern pattern = Pattern.compile("boundary=(?:\"([^\"]+)\"|([^;\\s]+))", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(contentType);
        if (matcher.find()) {
            return matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
        }
        return null;
    }

    // ==================== Junk Data Generators ====================

    private String generateRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private String generateRandomParam() {
        String prefix = PARAM_PREFIXES[random.nextInt(PARAM_PREFIXES.length)];
        String suffix = generateRandomString(random.nextInt(5) + 4);
        return prefix + suffix;
    }

    private String injectUrlEncoded(String body, int sizeBytes) {
        String paramName = generateRandomParam();
        int overhead = paramName.length() + 2; // = and &
        int valueLen = Math.max(0, sizeBytes - overhead);

        String junk = paramName + "=" + generateRandomString(valueLen);

        if (body == null || body.isEmpty()) {
            return junk;
        }
        return junk + "&" + body;
    }

    private String injectJson(String body, int sizeBytes) {
        if (body == null || body.trim().isEmpty()) {
            return null;
        }

        // Handle BOM
        String processBody = body;
        String bomPrefix = "";
        if (body.length() >= 1 && body.charAt(0) == '\uFEFF') {
            bomPrefix = "\uFEFF";
            processBody = body.substring(1);
        }

        String trimmed = processBody.trim();

        if (trimmed.startsWith("{")) {
            String result = injectJsonObject(processBody, sizeBytes);
            return result != null ? bomPrefix + result : null;
        } else if (trimmed.startsWith("[")) {
            String result = injectJsonArray(processBody, sizeBytes);
            return result != null ? bomPrefix + result : null;
        }

        return null;
    }

    private String injectJsonObject(String body, int sizeBytes) {
        // Find first {
        int braceIndex = body.indexOf('{');
        if (braceIndex == -1) return null;

        int contentStart = braceIndex + 1;
        int bodyLen = body.length();

        // Find first non-whitespace after {
        int firstNonWs = contentStart;
        while (firstNonWs < bodyLen && isJsonWhitespace(body.charAt(firstNonWs))) {
            firstNonWs++;
        }

        // Find closing brace to check if empty
        int closingBrace = body.lastIndexOf('}');
        boolean isEmpty = (firstNonWs >= closingBrace);

        // Capture indentation (whitespace between { and first content)
        String indent = (firstNonWs > contentStart) ? body.substring(contentStart, firstNonWs) : "";

        // Build suffix: if empty object, just indent; otherwise comma + indent
        String suffix;
        if (isEmpty) {
            suffix = indent.isEmpty() ? "" : indent;
        } else {
            suffix = "," + indent;
        }

        // Build junk field
        String paramName = generateRandomParam();
        int overhead = paramName.length() + 5 + suffix.length(); // "":"" + suffix
        int valueLen = Math.max(0, sizeBytes - overhead);

        String junkField = "\"" + paramName + "\":\"" + generateRandomString(valueLen) + "\"" + suffix;

        // Insert at first non-whitespace position (preserving original indent)
        return body.substring(0, firstNonWs) + junkField + body.substring(firstNonWs);
    }

    private boolean isJsonWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    private String injectJsonArray(String body, int sizeBytes) {
        // Find first [
        int bracketIndex = body.indexOf('[');
        if (bracketIndex == -1) return null;

        int contentStart = bracketIndex + 1;
        int bodyLen = body.length();

        // Find first non-whitespace after [
        int firstNonWs = contentStart;
        while (firstNonWs < bodyLen && isJsonWhitespace(body.charAt(firstNonWs))) {
            firstNonWs++;
        }

        // Find closing bracket to check if empty
        int closingBracket = body.lastIndexOf(']');
        boolean isEmpty = (firstNonWs >= closingBracket);

        // Capture indentation (whitespace between [ and first content)
        String indent = (firstNonWs > contentStart) ? body.substring(contentStart, firstNonWs) : "";

        // Build suffix: if empty array, just indent; otherwise comma + indent
        String suffix;
        if (isEmpty) {
            suffix = indent.isEmpty() ? "" : indent;
        } else {
            suffix = "," + indent;
        }

        // Build junk element
        int overhead = 2 + suffix.length(); // "" + suffix
        int valueLen = Math.max(0, sizeBytes - overhead);

        String junkElement = "\"" + generateRandomString(valueLen) + "\"" + suffix;

        // Insert at first non-whitespace position (preserving original indent)
        return body.substring(0, firstNonWs) + junkElement + body.substring(firstNonWs);
    }

    private String injectXml(String body, int sizeBytes) {
        int overhead = 7; // <!---->
        int contentLen = Math.max(0, sizeBytes - overhead);

        String comment = "<!--" + generateRandomString(contentLen) + "-->";

        // Insert after XML declaration if present, otherwise at beginning
        if (body == null || body.isEmpty()) {
            return comment;
        }

        // Handle BOM (UTF-8 BOM is 0xEF 0xBB 0xBF, which is \uFEFF in Java String)
        int start = 0;
        if (body.length() >= 1 && body.charAt(0) == '\uFEFF') {
            start = 1;
        }

        // Skip leading whitespace
        while (start < body.length() && isXmlWhitespace(body.charAt(start))) {
            start++;
        }

        // Check for XML declaration <?xml ... ?>
        int insertPos = start;
        if (body.length() > start + 5) {
            String possibleDecl = body.substring(start, Math.min(start + 5, body.length())).toLowerCase();
            if (possibleDecl.startsWith("<?xml")) {
                int declEnd = body.indexOf("?>", start + 5);
                if (declEnd != -1) {
                    insertPos = declEnd + 2;
                }
            }
        }

        return body.substring(0, insertPos) + comment + body.substring(insertPos);
    }

    private boolean isXmlWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    private String injectMultipart(String body, String boundary, int sizeBytes) {
        String paramName = generateRandomParam();
        String template = "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n";

        int overhead = String.format(template, boundary, paramName, "").length();
        int contentLen = Math.max(0, sizeBytes - overhead);

        String junkPart = String.format(template, boundary, paramName, generateRandomString(contentLen));

        // Insert at the beginning of body (before first boundary)
        int firstBoundary = body.indexOf("--" + boundary);
        if (firstBoundary == -1) {
            return junkPart + body;
        }

        return body.substring(0, firstBoundary) + junkPart + body.substring(firstBoundary);
    }

    private String injectTextPlain(String body, int sizeBytes) {
        String junk = generateRandomString(sizeBytes);
        if (body == null || body.isEmpty()) {
            return junk;
        }
        return junk + "\n" + body;
    }

    private String injectLineComment(String body, int sizeBytes, String prefix) {
        int overhead = prefix.length() + 1; // prefix + newline
        int contentLen = Math.max(0, sizeBytes - overhead);

        String comment = prefix + generateRandomString(contentLen) + "\n";

        if (body == null || body.isEmpty()) {
            return comment;
        }
        return comment + body;
    }

    private String injectJsonLines(String body, int sizeBytes) {
        if (body == null || body.isEmpty()) {
            // Default to object format for empty body
            String paramName = generateRandomParam();
            int overhead = paramName.length() + 7;
            int valueLen = Math.max(0, sizeBytes - overhead);
            return "{\"" + paramName + "\":\"" + generateRandomString(valueLen) + "\"}\n";
        }

        // Skip BOM if present
        String processBody = body;
        if (body.length() >= 1 && body.charAt(0) == '\uFEFF') {
            processBody = body.substring(1);
        }

        // Find first non-empty line to detect format (object or array)
        String[] lines = processBody.split("\n", 2);
        String firstLine = lines[0].trim();

        if (firstLine.startsWith("{")) {
            // JSON object line - inject object
            String paramName = generateRandomParam();
            int overhead = paramName.length() + 7;
            int valueLen = Math.max(0, sizeBytes - overhead);
            String junkLine = "{\"" + paramName + "\":\"" + generateRandomString(valueLen) + "\"}\n";
            return junkLine + body;
        } else if (firstLine.startsWith("[")) {
            // JSON array line - inject array
            int overhead = 4; // [""]\n
            int valueLen = Math.max(0, sizeBytes - overhead);
            String junkLine = "[\"" + generateRandomString(valueLen) + "\"]\n";
            return junkLine + body;
        }

        // Default to object format
        String paramName = generateRandomParam();
        int overhead = paramName.length() + 7;
        int valueLen = Math.max(0, sizeBytes - overhead);
        return "{\"" + paramName + "\":\"" + generateRandomString(valueLen) + "\"}\n" + body;
    }

    private String injectCsv(String body, int sizeBytes) {
        int numColumns = random.nextInt(6) + 3; // 3-8 columns
        int overhead = numColumns; // commas + newline
        int contentPerCol = Math.max(1, (sizeBytes - overhead) / numColumns);

        StringBuilder row = new StringBuilder();
        for (int i = 0; i < numColumns; i++) {
            if (i > 0) row.append(",");
            row.append(generateRandomString(contentPerCol));
        }
        row.append("\n");

        if (body == null || body.isEmpty()) {
            return row.toString();
        }
        // Append junk row at the end (matching Python behavior)
        return body + row.toString();
    }
}
