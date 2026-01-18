# This "nowafpls V2" based on https://github.com/assetnote/nowafpls by Shubham Shah (https://github.com/infosec-au)
# Improved and maintained by Irwan Kusuma (https://www.linkedin.com/in/donesia)
from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IRequestInfo, IContextMenuInvocation
from javax.swing import JMenuItem, JLabel, JTextField, JOptionPane, JPanel, JFrame
import javax.swing as swing
from java.util import ArrayList
from java.lang import Throwable
from collections import deque
from java.io import ByteArrayOutputStream
import re
import random
import string
import time
import traceback

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("nowafpls V2 (https://www.linkedin.com/in/donesia)")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        self._auto_inject_enabled = self._load_bool_setting("auto_inject_enabled", False)
        self._auto_inject_kb = self._load_int_setting("auto_inject_kb", 128)
        self._alert_last = {}
        self._missing_ct_paths = set()
        self._missing_ct_order = deque()
        self._missing_ct_limit = 5000

    def createMenuItems(self, invocation):
        if invocation is None:
            return ArrayList()
        try:
            invocation_context = invocation.getInvocationContext()
            if invocation_context is None:
                return ArrayList()
            try:
                tool_flag = invocation.getToolFlag()
            except Throwable:
                tool_flag = None
            self.context = invocation
            menu_list = ArrayList()
            allowed_contexts = set([IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST])
            for name in ("CONTEXT_INTRUDER_ATTACK_RESULTS",):
                value = getattr(IContextMenuInvocation, name, None)
                if value is not None:
                    allowed_contexts.add(value)

            intruder_payload_ctx = getattr(IContextMenuInvocation, "CONTEXT_INTRUDER_PAYLOAD_POSITIONS", None)
            if intruder_payload_ctx is not None and invocation_context == intruder_payload_ctx:
                return ArrayList()
            if tool_flag == self._callbacks.TOOL_INTRUDER and invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                return ArrayList()

            allow_insert = invocation_context in allowed_contexts
            if not allow_insert:
                try:
                    messages = invocation.getSelectedMessages()
                    if messages and messages[0].getRequest() is not None:
                        allow_insert = True
                except Throwable:
                    pass

            if allow_insert:
                menu_list.add(JMenuItem("Insert Junk Data Size", actionPerformed=self.insert_random_data))
            menu_list.add(JMenuItem(self._auto_inject_label(), actionPerformed=self.toggle_auto_inject))
            menu_list.add(JMenuItem(self._auto_inject_size_label(), actionPerformed=self.set_auto_inject_size))
            return menu_list
        except Throwable:
            self._log_error("createMenuItems")
            return ArrayList()

    def _auto_inject_label(self):
        status = "ON" if self._auto_inject_enabled else "OFF"
        return "Auto-Inject (Scanner): " + status

    def _auto_inject_size_label(self):
        return "Set Auto-Inject Size (KB) [" + str(self._auto_inject_kb) + "]"

    def _load_bool_setting(self, key, default):
        value = self._callbacks.loadExtensionSetting(key)
        if value is None:
            return default
        return value.lower() in ("1", "true", "yes", "on")

    def _load_int_setting(self, key, default):
        value = self._callbacks.loadExtensionSetting(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _log_error(self, context):
        message = "[nowafpls V2] Error in {0}:\n{1}".format(context, traceback.format_exc())
        try:
            self._callbacks.printError(message)
        except Exception:
            pass

    def _alert_error(self, context, rate_limit=True):
        try:
            now = time.time()
            if rate_limit:
                last = self._alert_last.get(context, 0)
                if now - last < 60:
                    return
                self._alert_last[context] = now
            self._callbacks.issueAlert("[nowafpls V2] Error in {0}. See Extender output.".format(context))
        except Exception:
            pass

    def _body_has_content(self, request, request_info):
        body_offset = request_info.getBodyOffset()
        return body_offset < len(request)

    def _has_content_type_header(self, request_info):
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                value = header.split(":", 1)[1].strip()
                return value != ""
        return False

    def _get_request_method(self, request_info):
        try:
            method = request_info.getMethod()
            if method:
                return method
        except Exception:
            pass
        try:
            headers = request_info.getHeaders()
            if headers:
                parts = headers[0].split(" ")
                if parts:
                    return parts[0]
        except Exception:
            pass
        return "UNKNOWN"

    def _get_request_path(self, request_info):
        try:
            url = request_info.getUrl()
            if url is not None:
                path = url.getPath()
                if not path:
                    path = "/"
                return path
        except Throwable:
            pass
        try:
            headers = request_info.getHeaders()
            if headers:
                parts = headers[0].split(" ")
                if len(parts) >= 2:
                    path = parts[1]
                    if "?" in path:
                        path = path.split("?", 1)[0]
                    return path
        except Throwable:
            pass
        return None

    def _get_request_host(self, request_info):
        try:
            url = request_info.getUrl()
            if url is not None:
                host = url.getHost()
                if host:
                    return host
        except Throwable:
            pass
        try:
            headers = request_info.getHeaders()
            for header in headers:
                if header.lower().startswith("host:"):
                    host = header.split(":", 1)[1].strip()
                    if host:
                        return host
        except Throwable:
            pass
        return None

    def _get_full_url(self, request_info):
        try:
            url = request_info.getUrl()
            if url is not None:
                return url.toString()
        except Throwable:
            pass
        try:
            headers = request_info.getHeaders()
            path = None
            if headers:
                parts = headers[0].split(" ")
                if len(parts) >= 2:
                    path = parts[1]
            host = self._get_request_host(request_info)
            if host and path:
                return host + path
            if host:
                return host
            if path:
                return path
        except Throwable:
            pass
        return "<unknown url>"

    def _maybe_log_missing_content_type(self, request, request_info):
        if not self._body_has_content(request, request_info):
            return
        has_header = self._has_content_type_header(request_info)
        if has_header and self._is_supported_content_type(request_info):
            return
        method = self._get_request_method(request_info)
        full_url = self._get_full_url(request_info)
        key = (method, full_url)
        if key in self._missing_ct_paths:
            return
        self._missing_ct_paths.add(key)
        self._missing_ct_order.append(key)
        if len(self._missing_ct_paths) > self._missing_ct_limit:
            while len(self._missing_ct_paths) > self._missing_ct_limit:
                old_key = self._missing_ct_order.popleft()
                self._missing_ct_paths.discard(old_key)
        try:
            raw_content_type = self._get_raw_content_type(request_info)
            if not has_header:
                raw_content_type = "<missing>"
            elif not raw_content_type:
                raw_content_type = "<unknown>"
            self._callbacks.printOutput(
                "[nowafpls V2] Unsupported or missing Content-Type with body: {0} {1} (Content-Type: {2})".format(
                    method, full_url, raw_content_type
                )
            )
        except Exception:
            pass

    def _mark_junk_comment(self, message_info):
        try:
            existing = message_info.getComment()
            if existing:
                if "Junk Data" in existing:
                    return
                message_info.setComment(existing + " | Junk Data")
            else:
                message_info.setComment("Junk Data")
        except Throwable:
            pass
        except Exception:
            pass


    def generate_random_string(self, length, charset=None):
        if charset is None:
            charset = string.ascii_letters + string.digits
        return ''.join(random.choice(charset) for _ in range(length))

    def generate_random_param(self):
        prefixes = ['id', 'user', 'session', 'token', 'auth', 'request', 'data', 'temp', 'cache', 'author','authorID','authorName','authorityType','authorize','authorized','authorizedkeys','authors','authorship','authserver','authtype','auto','autoaddfields','autoadjust','autoapprove','autoassign','autocomplete','autodel','autodeltime','autoedge','autoenable','autofix','autofixforcedest','autofixforcesource','autofocus','autogroup','autologin','automatic','autoplay','autoptp','autoredirect','autorefresh','autosave','autoupdate','avatar','avatars','b','bID','baba','back','backcconnmsg','backcconnmsge','backconnectport','backdrop','backend','background','backto','backup','backuparea','backupbeforeupgrade','backupcount','backupnow','backuptype','backurl','baddress1','baddress2','badfiles','balance','ban','bandwidth','banid','banip','bank','banned','bannedUser','banner','banreason','bansubmit','bantime','bantype','bar','barcode','base','base64','basedn','basemodule','baseurl','basic','basket','baslik','batch','batchExtend','batchID','baz','baza','bbc','bbconfigloc','bbox','bcc','bcip','bcity','bconfirmemail','bcountry','bday2','bduss','be','before','begin','beginner','behaviour','bemail','benchmark','beta','bfirstname','bg','bgColor','bgc','bgcolor','bi','bib','biblioID','biblioTitle','bid','bill','billing','binary','binddn','binding','bindip','bindpw','bio','bip','birth','birthDate','birthdate','birthday','birthmonth','birthplace','birthyear','bitrate','bits','blacklist','blastname','blatent','block','blockbogons','blockedafter','blockedmacsurl','blockeduntil','blockid','blocklabel','blockpriv','blocks','blog','blogbody','blogid','blogname','blogs','blogtags','blogtitle','blogusers','board','boardaccess','boardid','boardmod','boardprofile','boards','boardseen','boardtheme','boardurl','body','bodytext','bogonsinterval','bomb','bonus','book','bookings','bookmark','bool','boolean','bootslice','bootstrap','border','bots','bottom','bounce','box','box1','box2','box3','boxes','bpage','bpg','bphone','bport','bps','branch','brand','brd','breadcrumb','break','breakdown','breakpoint','breakpoints','bridge','bridgeif','broadcast','broken','browse','browser','bs','bstate','btn','btnSubmit','bucket','buddies','budget','bug','build','bulk','bulletin','business','businessName','button','buttons','buttonval','buy','bv','bwdefaultdn','bwdefaultup','by','byapache','bycw','bye','byetc','byfc','byfc9','byoc','bypassstaticroutes','bypcu','bysyml','bythis','byws','bzipcode','c','c2','c37url','c99shcook','cID','cP','cPath','cable','cache','cacheable','cached','caching','caid','cainfo','cal','calcolor','calendar','calendarid','calid','call','callNumber','callback','callbackPW','caller','callerId','callerid','callf','callop','calname','cambio','campaign','campaignid','campo','cancel','canceldelete','cancelled','caneditdomain','caneditphpsettings','canned','canpreview','cantidad','canvas','cap','captcha','caption','capture','card','cardno','cardtype','caref','cart','cartId','case','casein','cat','catID','catId','catalogName','catalogid','categories','category','categoryID','categoryName','categoryid','categoryname','cateid','catid','catname','catorder','cats','catslist','cb','cc','cd','cdir','cdirname','cdone','cds','censorIgnoreCase','censorWholeWord','censortest','censortext','cep','cert','certdepth','certid','certificate','certref','certsubject','cf','cfed','cfg','cfgkey','cfgval','cfil','cfile','cfilename','cfx','cfy','ch','challenge','chan','change','changePass','changeUserGroup','changeVisitAlpha','changecurrent','changed','changeit','changepassword','changero','changes','changestatus','changeusername','chanid','channel','channelID','channelName','channelmode','channels','chapo','chapter','char','characterid','characters','charge','chars','charset','charsout','chart','chartSettings','chartsize','chat','chatmsg','chats','chdir','check','check1','checkReshare','checkShares','checkaliasesurlcert','checkbox','checkboxes','checkconnect','checked','checkemail','checkid','checking','checkmetadesc','checknum','checkout','checkprivsdb','checkprivstable','checksum','checksumbits','chfl','child','children','chk','chkagree','chkalldocs','chm','chmod','chmod0','chmodenum','chmodnow','choice','choice2','choix','chosen','chpage','chromeless','chunk','chunks','chvalue','cid','cids','cinterface','cipher','city','ck','ckeditor','cktime','cl','claim','class','classOptions','classification','classname','clay','clean','cleancache','cleanup','clear','clearLog','clearLogs','clearSess','clearcache','cleared','clearlogs','clearquery','clearsql','cleartokens','cli','clicked','clickedon','client','clientId','clientcookies','clientid','clipboard','clockstats','clone','close','closed','closedate','closenotice','cls','cluster','cm','cmd','cmde','cmdex','cmdid','cmdir','cmdr','cmediafix','cmmd','cmode','cms','cmsadmin','cmsadminemail','cmspassword','cmspasswordconfirm','cn','cname','cnpj','co','coM','coauthors','cod','code','codeblock','coded','codepress','codes','codetype','coin','col','colName','collType','collTypeID','collTypeName','collapse','collation','collectcolumn','collection','collectionfrom','collectionto','college','colltype','color','color1','color2','colors','colours','cols','column','columnIndex','columns','columnsToDisplay','com','combine','combo','command','commander','comment','commentId','commentaire','commentid','comments','commenttext','commex','commit','commits','commonName','communication','community','comp','compact','company','compare','complete','completed','component','compose','compr','compress','compression','con','concepto','condition','conditions','conf','config','configfile','configs','configuration','configure','confirm','confirm2','confirm3','confirmEmail','confirmFinish','confirmPassword','confirmation','confirmdelete','confirmed','confirmpassword','conflict','conn','connect','connectback','connection','connectionType','connections','connectt','connport','connsub','consent','consoleview','const','constraint','consumer','consumerKey','consumerSecret','cont','contact','contactEmail','contactID','contactId','contactName','contactid','contactidlist','contactname','contacts','container','containerid','contains','contbutt','content','content1','contentDesc','contentPath','contentTitle','contentType','contents','contenttype','contest','context','continue','control','controller','controllers','conv','conversation','convert','convertmode','cookie','cookielength','cookiename','cookies','coord','coords','cop','copied','coppa','coppaFax','coppaPost','copy','copyname','copyright','core','correctcase','cost','count','counter','countonly','country','countryCode','countryID','countryName','counts','coupling','coupon','couponamount','couponcode','course','courseId','courses','cover','coverage','cp','cpage','cpass','cpath','cpu','cpw','cpy','cpyto','cr','cracK','crannycap','crcf','crdir','cre','create','createaccount','createclass','created','createdb','createdon','createfolder','createlist','createmode','createpages','createstdsubdomain','createuser','createview','credentials','credit','creditCardNumber','creditCardType','credits','crefile','criteria','criteriaAndOrColumn','criteriaAndOrRow','criteriaColumn','criteriaColumnAdd','criteriaColumnCollations','criteriaColumnCount','criteriaColumnDelete','criteriaColumnInsert','criteriaColumnName','criteriaColumnNames','criteriaColumnOperators','criteriaColumnTypes','criteriaRowAdd','criteriaRowDelete','criteriaRowInsert','criteriaSearchString','criteriaSearchType','criteriaShow','criteriaSort','criteriaTables','criteriaValues','cron','crop','cropDetails','crrt','crt','crtty','crypo','crypt','cs','cs1','cs2','csid','csr','csrf','csrftoken','css','csspreview','csv','csvIDs','ct','ctag','ctf','ctid','ctrl','ctx','ctype','cuenta','cur','curdir','curfile','curl','curpage','curpath','curr','currency','currencyCode','currencyCodeType','currencyid','current','currentFolder','currentFolderPath','currentPage','currentPassword','currentday','currentid','cursor','cust','custid','custom','customFieldId','customId','customWhereClause','customaddtplid','customcss','customer','customerid','customernumber','customers','customfield','customized','cut','cvmodule','cvv','cvv2Number','cw','cx','cy','d','d1','d2','dB','dID','daemon','dare','darezz','dashboard','data','data2','dataLabel','dataType','dataangle','database','databasehost','databaseloginname','databaseloginpassword','databasename','databases','datadir','dataflt','datagapangle','datagapradius','dataofs','dataroot','dataset','datasrt','datatype','dataurl','date','date1','date2','dateEnd','dateExpected','dateFormat','dateReceived','dateStart','datechange','dateformat','datefrom','dates','datestamp','datetime','dateto','datetype','day','dayDelta','dayname','days','db','dbHost','dbName','dbOP','dbPass','dbPassword','dbPort','dbPrefix','dbPwd','dbTablePrefix','dbType','dbUser','dbUsername','dbase','dbbase','dbg','dbh','dbhost','dbid','dbms','dbn','dbname','dbp','dbpass','dbpassword','dbport','dbprefix','dbpw','dbserver','dbsession','dbsize','dbsocket','dbstats','dbtype','dbu','dbuser','dbusername','dc','dccharset','dd','ddnsdomain','ddnsdomainkey','ddnsdomainkeyname','ddnsdomainprimary','ddnsupdate','ddo','deL','deS','deact','deactivate','deactivated','deadfilescheck','deadline','deathdate','deathplace','debet','debit','debug','debug2','debug3','debugbox','debugfailover','debugmethods','decline','decode','decoded','decomposition','decrypt','deduction','def','default','defaultValue','defaultgw','defaultleasetime','defaultqueue','defaults','defaulttemplate','deftime','degrees','del','delName','delall','delay','deld','deldat','deldir','delete','deleteAccount','deleteCategory','deleteImage','deleteImages','deleteIndex','deleteList','deletePrices','deleteUser','deleteUserGroup','deleteUsers','deleteall','deletebookmarks','deletecheck','deletecntlist','deletecomment','deleted','deletedSpecs','deletedir','deleteevent','deletefile','deletefolder','deleteg','deletegrp','deleteid','deleteip','deletemeta','deletepage','deletepms','deletepost','deleterule','deletesmiley','deletesubmit','deleteuser','deleteweek','delf','delfbadmin','delfile','delfl','delfolder','delfriend','delgroup','delid','delim','delimeter','delimiter','deliver','deliveries','delivery','delmac','delmarked','delpref','delregname','delrow','delrule','delsel','delstring','delsub','deltpl','deltype','deluser','demo','demoData','demolish','dend','denied','deny','denyunknown','department','depid','deposit','dept','depth','deptid','depts','des','desact','desc','desc1','desc2','descending','descr','descripcion','description','design','dest','destd','destination','destino','destslice','detached','detail','detail0','details','dev','device','deviceid','devid','df','dfilename','dfrom','dhcp','dhcp6prefixonly','dhcp6usev4iface','dhcpbackup','dhcpfirst','dhcphostname','dhcpleaseinlocaltime','dhcprejectfrom','dhcpv6leaseinlocaltime','dhtc','dialog','dict','dictionary','did','dif','diff','difficulty','dig','digest','dim','dimensions','dip','dipl','dir','dirList','dirToken','diract','dircreate','dire','direccion','direct','direction','directmode','director','directory','directoryscanner','dirfree','dirlisting','dirname','dirr','dirs','dirupload','dis','disable','disablebeep','disablecarp','disablecheck','disablechecksumoffloading','disableconsolemenu','disabled','disabledBBC','disablefilter','disablehttpredirect','disablelargereceiveoffloading','disablelocallogging','disablenegate','disablereplyto','disablescrub','disablesegmentationoffloading','disablevpnrules','disallow','disapprove','discard','discipline','discount','disk','diskspace','dismiss','disp','display','displayAllColumns','displayName','displayVisualization','displayname','distance','distinct','distribution','div','diversity','divider','dizin','dkim','dl','dl2','dlPath','dlconfig','dldone','dlgzip','dlt','dm','dmodule','dn','dname','dnpipe','dns1','dns2','dns3','dns4','dnsallowoverride','dnslocalhost','dnsquery','dnssec','dnssecstripped','dnssrcip','do','doDelete','doExport','doImport','doRegister','doSearch','doaction','doaction2','dob','doc','docgroup','docgroups','docid','docroot','docs','doctype','document','documentID','documentgroup','documentroot','doi','doimage','doinstall','doit','dolma','domaiN','domain','domainname','domains','domainsearchlist','domen','domerge','donated','done','donor','donotbackuprrd','dontFormat','dontlimitchars','dopt','dos','dosearch','dosthisserver','dosyaa','down','downchange','downf','downloaD','download','downloadIndex','downloadbackup','downloadbtn','downloaded','downloadid','downloadpos','dp','dpath','dpgn','draft','dragdroporder','dragtable','drilldown','driver','drop','dropped','droptables','dry','dryrun','dscp','dst','dstbeginport','dstendport','dstip','dstmask','dstnot','dstport','dsttype','dt','dtend','dto','dtstart','due','duedate','duid','dumd','dummy','dump','dup','dupfiles','duplicate','duration','dwld','dxdir','dxdirsimple','dxfile','dximg','dxinstant','dxmode','dxparam','dxportscan','dxsqlsearch','dxval','dynamic','e','ealgo','ec','echostr','ecotax','ecraz','ed','eday','edge','edit','editParts','editUserGroup','editUserGroupSubmit','editable','editaction','edited','editedon','editf','editfile','editfilename','editform','editgroup','editid','editing','edition','editkey','editor','editprofile','edittxt','edituser','editwidget','education','ee','ef','eheight','eid','eids','elastic','element','elementId','elementType','elements','em','email','email1','email2','emailActivate','emailAddress','emailBody','emailID','emailId','emailList','emailToken','emailaddress','emailch','emailcomplete','emailfrom','emailnotif','emails','emailsubject','emailto','embed','embedded','eml','emonth','emphasis','empty','emptygenres','en','enable','enableReserve','enablebinatreflection','enabled','enablenatreflectionhelper','enableserial','enablesshd','enablestp','enc','enclose','encod','encode','encoded','encodedbydistribution','encoder','encoderoptionsdistribution','encoding','encrypt','encrypted','encryption','end','endDate','enddate','endday','endmonth','endpoint','endport','ends','endtime','endyear','enforceHTTPS','engine','enhanced','enquiry','enroll','entire','entity','entityID','entityid','entries','entry','entryID','entryId','entryPoint','entryid','env','eol','ep','ephp','episode','epoch','epot','erne','erorr','err','errmsg','error','error403path','error404path','error500path','errorCode','errormail','errormsg','errors','errorstr','errorswarnings','esId','eshopAccount','eshopId','et','eta','etag','evac','eval','evalcode','evalinfect','evalsource','evap','event','eventDate','eventID','eventId','eventName','eventTitle','eventid','eventname','events','evtitle','ewidth','ex','exT','exTime','exact','example','exc','exccat','except','exception','excerpt','exchange','exclude','excludedRecords','exe','exec','execmassdeface','execmethod','execute','executeForm','exemplar','exif','existing','exists','exitsql','exp','expDate','expDateMonth','expDateYear','expand','expandAll','expanded','expertise','expid','expiration','expirationDate','expirationmonth','expirationyear','expire','expires','expiry','explain','exploit','exponent','export','exportDetail','exportFile','exportFormat','exportFrames','exportImages','exportMisc','exportVideo','ext','extAction','extMethod','extTID','extUpload','extdir','extdisplay','extend','extended','extension','extensions','extern','external','extra','extractDir','extras','eyear','ezID','f','f2','fCancel','fID','fType','facebook','facid','facility','fail','failed','failure','fallback','fam','family','familyName','fast','fav','favicon','favicons','favorites','favourite','fax','fbclearall','fc','fchmod','fcksource','fcopy','fcsubmit','fdel','fdelete','fdo','fdownload','fe','feature','featured','features','fedit','fee','feed','feedId','feedback','feeds','feedurl','feid','fetch','ffile','fg','fh','fheight','fid','fid2','field','field1','field2','fieldCounter','fieldEnc','fieldId','fieldName','fieldSep','fieldType','fieldValue','fieldid','fieldkey','fieldlabel','fieldname','fields','fieldtype','filE','file','file2ch','fileContent','fileDataName','fileDesc','fileDir','fileEdit','fileExistsAction','fileFormat','fileID','fileLength','fileName','fileOffset','fileTitle','fileType','fileURL','fileact','filecontent','filecontents','filecount','filecreate','fileext','fileextensions','fileframe','filefrom','fileid','filelist','filename','filename2','filename32','filename64','filenamepattern','filenew','fileoffset','fileold','filepath','fileperm','files','filesend','filesize','fileto','filetosave','filetotal','filetype','filetypelist','fileurl','filew','fill','filled','filter','filterAlert','filterCategory','filterName','filterText','filterdescriptions','filterlogentries','filterlogentriesinterfaces','filters','filtertext','filtertype','filtre','fin','find','findString','findid','finds','fineEachDay','finesDate','finesDesc','finish','finishID','finished','firmwareurl','first','firstName','firstday','firstname','fix','fixErrors','fixid3v1padding','fixmetadesc','fl','flag','flags','flash','flashpga','flashtype','fld','fldDecimal','fldLabel','fldLength','fldMandatory','fldName','fldPickList','fldType','flddecimal','fldlabel','fldlength','fldname','fldr','flip','floating','floor','flow','flowtable','flush','flushcache','fm','fmt','fn','fname','focus','foffset','folder','folderID','folderId','folderid','foldername','folderpath','folders','foldmenu','follow','following','followup','font','fontSize','fontb','fontcolor','fontdisplay','fonte','fontg','fontr','fontsize','foo','foo1','foo2','foo6','footer','for','force','forceFormat','forceIcon','forceRefresh','foreground','foreign','foreignDb','foreignTable','forever','forgot','forgotPassword','form','formAutosave','formId','formName','formSubmit','formage','format','formatdistribution','formatdown','formats','formatup','formdata','formfactor','formid','formname','forum','forumid','forums','forward','forwarderid','forwarding','fp','fpassw','fpath','fq','fqdn','fragment','frame','framed','frames','free','frequency','frequencyID','frequencyName','fresh','friend','friendlyiface','friends','frm','frob','from','fromAddress','fromdate','fromemail','fromname','fromsearch','front','frontend','frontpage','fs','fsOP','fstype','ft','ftp','ftphost','ftppass','ftps','ftpscanner','ftpuser','ftype','fu','full','fullfolder','fullname','fullsite','fulltext','func','funcs','function','functionp','functionz','fuzz','fvonly','fw','fwdelay','fwidth','fyear','g','gID','ga','gadget','gallery','game','gameID','gameid','gateway','gatewayv6','gbid','gc','gd','gdork','geT','ged','gen','gender','general','generalgroup','generate','generateKeypair','generated','generatekey','generic','genre','genredistribution','geoOption','get','getDropdownValues','getInfos','getOutputCompression','getThermalSensorsData','getactivity','getcfg','getdate','getdb','getdyndnsstatus','getenv','getfile','getm','getpic','getprogress','getstatus','getupdatestatus','gf','gfils','ggid','gid','gids','gifif','gift','gip','github','giveout','global','gmd','gmdCode','gmdID','gmdName','gn','go','goal','goback','godashboard','godb','gold','gomkf','goodfiles','goodsid','google','googleplus','goto','gotod','gpack','gpsflag1','gpsflag2','gpsflag3','gpsflag4','gpsfudge1','gpsfudge2','gpsinitcmd','gpsnmea','gpsport','gpsprefer','gpsrefid','gpsselect','gpsspeed','gpsstratum','gpssubsec','gpstype','gr','grabs','gracePeriode','grade','grant','granted','grants','granularity','graph','graphid','graphlot','graphtype','greif','grid','group','groupCounter','groupID','groupIDs','groupId','groupName','groupby','groupdel','groupdesc','grouped','groupfilter','groupid','groupname','groupr','groupreason','groups','grouptype','grp','grpage','grps','grupo','gs','gt','gtin','gtype','guest','guestname','guid','gx','gz','gzip','h','ham','handle','handler','harddiskstandby','hardenglue','harm','hasAudio','hash','hashed','hashkey','hashtoh','having','hc','hd','hdnProductId','head','header','headerimage','headers','heading','headline','health','height','hello','hellotime','help','hex','hh','hid','hidFileID','hidden','hide','hideNavItem','hideidentity','hidem','hidemenu','hideversion','hidid','hidrfile','highlight','history','hit','hl','hldb','hlp','hname','holDate','holDateEnd','holDesc','holdcnt','holiday','home','homepage','hook','horario','hosT','host','hostName','hostapd','hostid','hostipformat','hostname','hostres','hosts','hot','hour','hours','how','howlong','howmany','howmuch','hp','href','hrs','hs','htaccess','htaccessnew','htc','htcc','html','html2xhtml','htmlemail','http_host','httpbanner','https','httpscanner','httpsname','httpsverify','htype','hwhy','i','iColumns','iDisplayLength','iDisplayStart','iLength','iSortingCols','iStart','ical','icerik','icmptype','icode','icon','icp','icq','id','id1','id10gid','id10level','id11gid','id11level','id12gid','id12level','id13gid','id13level','id14gid','id14level','id15gid','id15level','id16gid','id16level','id17gid','id17level','id18gid','id18level','id19gid','id19level','id1gid','id1level','id2','id20gid','id20level','id21gid','id21level','id22gid','id22level','id23gid','id23level','id24gid','id24level','id25gid','id25level','id26gid','id26level','id27gid','id27level','id28gid','id28level','id29gid','id29level','id2gid','id2level','id30gid','id30level','id31gid','id31level','id32gid','id32level','id33gid','id33level','id34gid','id34level','id35gid','id35level','id36gid','id36level','id37gid','id37level','id38gid','id38level','id39gid','id39level','id3gid','id3level','id40gid','id40level','id4gid','id4level','id5gid','id5level','id6gid','id6level','id7gid','id7level','id8gid','id8level','id9gid','id9level','idL','idSelect','idSite','idb','idc','ident','identifiant','identifier','identity','idletimeout','idlist','idname','idp','ids','idstring','idtype','idx','ie','ieee8021x','if','ifname','ifnum','iframe','ignore','ignoreTV','ignored','ignorefatal','ignorephpver','ignoresubjectmismatch','iid','ikeid','ikesaid','imagE','image','imageThumbID','imageUrl','imagedetails','imagefile','imageid','imagename','images','imagesize','imaptest','imdb','imdbID','imdbid','img','imgid','imgpath','imgtype','imgurl','immediate','impersonate','import','importFile','importType','importaioseo','importance','important','importer','importfile','importid','importmethod','importonly','importrobotsmeta','in','inBindLog','inConfEmail','inDownLoad','inForgotPassword','inNewPass','inNewUserName','inPassword','inPopUp','inRemember','inSessionSecuirty','inUsername','inViewErrors','inViewLogs','inViewWarnings','inXML','inactive','inajax','iname','inc','incl','incldead','include','includenoncache','incspeed','indent','index','indexes','industry','indx','indxtxt','ineligible','inf3ct','info','inherit','inheritperm','inid','inifile','init','initdb','initdelay','initial','initialise','initialtext','initstr','injector','inline','input','inputH','inputSearchVal','inputSize','inputid','ins','insert','insertonly','insertonlybutton','inside','inst','instName','install','installGoingOn','installbind','installdata','installed','installmode','installpath','installstep','instance','instanceId','institution','int','intDatabaseIndex','intTimestamp','interest','interests','interface','interfaces','interval','intro','introeditor','inv','invalid','invalidate','invcDate','inventoryCode','inverse','invest','invitation','invite','invitecode','invited','inviteesid','invitepage','invites','invoice','invoiceId','invoiceid','ip','ipaddr','ipaddress','ipaddrv6','ipandport','ipexclude','iphone','iplist','ipp','ipproto','ipprotocol','iprestricted','ipscanner','ipsecpsk','ipv6allow','iron','isAjax','isDev','isDuplicate','isPending','isPersonal','isSwitch','isactive','isbinddomain','isbn','iscatchall','iscomment','iscustomreport','isdescending','isemaildomain','isenabled','isim','isnano','iso','isocode','ispersis','ispublic','issue','issues','isverify','it','item','itemAction','itemCode','itemCollID','itemID','itemId','itemName','itemShares','itemSite','itemSource','itemSourceName','itemStatus','itemStatusID','itemType','itemcount','itemid','itemkey','itemname','items','iv','j','jCryption','jabber','jahr','jax','jaxl','jenkins','jform','jid','jj','job','join','joindate','joined','joingroup','jpeg','js','json','jsoncallback','jsonp','jufinal','jump','jupart','k','k2','karma','katid','kb','keep','keepHTML','keeppass','keepslashes','key','key1','key2','keydata','keyid','keylen','keyname','keys','keystring','keytype','keyword','keywords','kick','kid','kil','kill','killfilter','kim','kime','kind','king','kod','kr','kstart','kw','l','l7container','lID','labdef','label','labelDesc','labelName','labels','laggif','lan','landscape','lane','lanes','lang','langCode','langID','langName','langname','langs','language','languageID','languagePrefix','languages','last','lastActive','lastID','lastName','lastQueryStr','lastactive','lastid','lastmodified','lastname','lasturl','lat','latencyhigh','latencylow','latest','latitude','layer','layers','layout','layoutType','lbcp','lbg','lcwidget','ld','ldap','lead','leadsource','leadval','leap','leaptxt','leave','lecture','left','legend','legendfont','legendfontb','legendfontg','legendfontr','legendfontsize','legendsize','legendstyle','lemail','len','length','letter','level','levels','lfilename','lib','library','license','lid','lifetime','lightbox','like','liked','lim','limit','limitTypes','limite','limitless','limitpage','line','lineid','lines','link','link0','link1','link2','linkcheck','linkedin','linkname','links','linktype','linkurl','list','listId','listInfo','listItem','listPrice','listShow','listSubmitted','listarea','listdirectory','liste','liste1','liste2','listid','listing','listmode','listname','listorder','listprice','lists','live','liveupdate','lm','ln','lname','lng','lngfile','load','loader','loan','loanID','loanLimit','loanPeriode','loanSessionID','loanStatus','loc','local','localbeginport','locale','localf','localfile','localip','localityName','localize','localized','location','locationID','locationName','locationid','locations','lock','locked','lockid','log','logFile','logMeIn','logType','logable','logall','logbogons','logdefaultblock','logdefaultpass','logeraser','logf','logfilE','logfile','logfilesize','loggedAt','loggedin','loggedout','logging','logic','logid','login','loginautocomplete','loginemail','loginguest','loginmessage','loginname','loglevel','loglighttpd','logo','logoff','logopng','logout','logoutRequest','logoutid','logpeer','logprivatenets','logs','logsys','logtype','lon','long','longitude','longlastingsession','longtitle','longurl','lookfornewversion','lookup','loop','loopstats','losshigh','losslow','lowercase','lp','ls','ls2','lst','lticket','lucky','m','m3u','m3uartist','m3ufilename','m3utitle','mD','mID','mKd','mKf','mSendm','mV','ma','mac','macname','magic','magicfields','mail','mailAuth','mailMethod','mailSubject','mailbody','mailbodyid','mailbox','mailcontent','mailid','mailing','maillisttmpname','mailsent','mailsub','mailto','mailtxt','main','mainGenre','mainmessage','maint','maintenance','maintitle','make','makedir','makedoc','makenote','makeupdate','man','manage','manager','managerlanguage','mandatory','manual','manufacturer','map','mapping','mark','markdefault','markdown','marked','marker','markread','masdr','mask','mass','massa','massdefacedir','massdefaceurl','massedit','masssource','massupload','master','match','matchcase','matchname','matchtype','matchuser','matchword','max','maxPlotLimit','maxResults','maxUploadSize','maxZipInputSize','maxaddr','maxage','maxcrop','maxdays','maxdiscards','maxentries','maxfan','maxgessper','maxgetfails','maximumstates','maximumtableentries','maxleasetime','maxmss','maxproc','maxprocperip','maxrejects','maxremfails','maxstales','maxstore','maxtemp','maxtime','maxtry','maxwidth','mbadmin','mbname','mbox','mc','mcid','md','md5','md5crack','md5datadupes','md5hash','md5pass','md5q','md5s','md5sig','md5sum','mdp','me','medalid','medalweek','media','mediaid','mediaopt','mediatype','mem','member','memberAddress','memberEmail','memberFax','memberID','memberName','memberNotes','memberPIN','memberPassWord','memberPasswd','memberPasswd2','memberPeriode','memberPhone','memberPostal','memberTypeID','memberTypeName','membergroups','membername','members','memday942','memday944','memo','memory','memtype','mensaje','menu','menuHashes','menuid','menuindex','menus','menutitle','merchantReference','merge','mergefile','meridiem','mess','message','messageMultiplier','messagebody','messageid','messages','messagesubject','meta','metadata','metakeyinput','metakeyselect','metavalue','method','methodpayload','methodsig','metric','metrics','mffw','mfldr','mfrom','mg','mh','mhash','mhost','mhpw','mhtc','mibii','microhistory','mid','mids','migrate','milw0','mime','mimetype','mimetypes','min','minCss','minJs','minViewability','minage','mini','minimum','minkills','minor','mins','minus','minute','minuteDelta','minutes','mip','mirror','misc','missing','missingtrackvolume','mito','mkD','mkF','mkdir','mkfile','ml','mlist','mlpage','mm','mmail','mmsg','mn','mnam','mobile','mobilephone','mobj','mod','modE','modal','modcat','modcomment','mode','modeextension','modeid','model','modelId','moderate','moderator','moderators','modfile','modfunc','modid','modified','modifiedSince','modifier','modify','modname','module','moduleDesc','moduleId','moduleName','modulePath','moduleType','moduleguid','moduleid','modulename','moduleorder','modules','moduletype','mon','money','mongo','monitor','monitorconfig','month','monthnum','months','mood','moodlewsrestformat','more','motd','motivo','mount','mountPoint','mountType','movd','move','moved','movedown','movefile','moveto','moveup','movie','movieview','mp','mpage','mpath','mpdconf','mquery','mrpage','mru','ms','msg','msg1','msgcachesize','msgexpired','msgfield','msgid','msgno','msgnoaccess','msgs','msgtype','msi','msid','msn','msq1','msqur','mss','mssql','mssqlcon','msubj','mtext','mtime','mto','mtu','mtype','multi','multifieldid','multifieldname','multiple','multiplier','muser','music','mute','mvdi','mve','mw','mx','myEditor','mybbdbh','mybbdbn','mybbdbp','mybbdbu','mybbindex','mybulletin','mycode','myip','mylogout','myname','mypassword','mysql','mysqlcon','mysqlpass','mysqls','mytribe','myusername','n','n1','nID','namE','name','name1','name2','name3','namefe','namelist','nameren','names','namespace','natport','natreflection','nav','navigation','nb','nc','ncbase','neg','nentries','nere','nested','netboot','netgraph','netmask','network','networkwide','new','newControl','newDir','newDirectory','newDueDate','newFileName','newGame','newGroup','newHeight','newLoanDate','newMonitor','newName','newPass','newPass2','newPassword','newPassword2','newPath','newPlaylistDescription','newPlaylistTitle','newProject','newSite','newText','newUser','newValue','newVideoCategory','newVideoDescription','newVideoTags','newVideoTitle','newWidth','newWindow','newX10Monitor','newaccount','newalbum','newcat','newcategory','newcode','newcontent','newdb','newdid','newdir','newdirectory','newdocgroup','newemail','newer','newf','newfile','newfolder','newgroup','newgroupname','newid','newids','newlang','newmessage','newname','newnick','newowner','newpage','newpass','newpass1','newpass2','newpassword','newpassword2','newpath','newpref','newprefix','newpw','newpw2','newpwd','newrule','news','newscan','newsid','newsletter','newstatus','newtag','newtemplate','newtext','newtheme','newtime','newtitle','newtype','newuser','newuseremail','newusergroup','newusername','newvalue','newver','newwin','next','nextPage','nextid','nextserver','nf','nf1','nf4c','nf4cs','nfid','nfile','nick','nickname','nid','njfontcolor','njform','njlowercolor','nmdf','nn','no','noChangeGroup','noOfBytes','noRedirect','noaction','noajax','noalert','noantilockout','noapi','nocache','nochange','noconcurrentlogins','noconfirmation','node','nodeid','nodnsrebindcheck','nodraft','noedit','noexpand','nogrants','noheader','nohtml','nohttpreferercheck','nohttpsforwards','nojs','nolang','nolimit','nolog','nom','nomacfilter','nombre','nome','nometool','nomodify','nonat','nonce','none','nonemptycomments','noofrows','nopackages','nopass','nopeer','nopfsync','noquery','nordr','noredir','noredirect','noreload','noserve','nosync','not','notactivated','notapache','notdeleted','note','noteid','notes','noti','notice','notices','notification','notificationCode','notificationType','notifications','notify','notmodrewrite','notrap','notsent','nounce','noupdate','nowarn','nowarned','nowmodule','noxml','np','npage','npassword','npassworda','npw','nr','nrows','nrresults','ns','nslookup','nsql','ntp1','ntp2','ntporphan','nuf','nuked','null','num','numExtended','numail','number','numberposts','numbers','numlabel','numwant','nurld','nurlen','nzbpath','o','oID','oauth','ob','obfuscate','obgz','obj','object','objectIDs','objects','oc','occ','occupation','odb','odbccon','odbcdsn','odbcpass','odbcuser','off','offline','offset','oid','oitar','ok','old','oldEmail','oldMountPoint','oldPassword','oldPlaylistTitle','oldaction','olddir','oldemail','older','oldfilename','oldform','oldname','oldpass','oldpassword','oldpasswrd','oldpwd','oldtime','oldusername','on','ondemand','online','onlyfind','onlyforuser','onserver','onserverover','onw','oof','op','opacHide','opauth','open','openbasedir','opened','opener','openid','openings','oper','operation','operations','operator','opml','opname','opt','optimization','optimize','optimizer','optin','option','options','opwd','or','oracle','oraclecon','orauser','ordDate','order','orderBy','orderByColumn','orderId','orderNo','orderType','orderby','orderbydate','orderdir','orderid','ordering','orders','org','orgajax','organization','organizationName','organizationalUnitName','orientation','origin','original','origname','orionprofile','os','ostlang','ot','other','otp','ouT','out','outbox','output','overdue','overmodsecurity','override','overrideID','overwrite','overwriteconfigxml','owner','ox','p','p1','p1entry','p1index','p2','p2ajax','p2entry','p2index','p2p','p3','p4ssw0rD','pDesc','pID','pMail','pName','pPage','pPass','pPassConf','pUID','pW','pa','paID','pack','package','packageName','padID','padding','page','pageID','pageId','pageOwner','pageSize','pageTitle','pageType','pageborder','paged','pageid','pagename','pageno','pagenow','pagenum','pagenumber','pageop','pages','pagesize','pagestart','pagestyle','pagetitle','pagination','paid','pais','palette','panel','paper','paporchap','param','param1','param2','parameter','parameters','params','paranoia','parent','parentID','parentId','parentfieldid','parentid','parentqueue','parenttab','parid','parked','parseSchema','part','partial','partition','partner','pasS','pass','pass1','pass2','passWord','passd','passenger','passf','passgen','passkey','passlength','passphrase','passthrumacadd','passthrumacaddusername','passw','passwd','passwd1','passwd2','passwdList','password','password1','password2','password3','passwordConfirm','passwordc','passwordconfirm','passwordfld','passwordfld1','passwordfld2','passwordgenmethod','passwordkey','passwordnotifymethod','passwords','passwrd','passwrd1','passwrd2','paste','patch','path','path2news','pathf','paths','pattern','pause','pay','payload','payment','paymentAmount','paymentData','paymentId','paymentStatus','paymentType','payments','paypal','paypalListener','pb','pc','pcid','pd','pdf','pdnpipe','pdocon','pdodsn','pdopass','pdouser','peace','peerstats','pending','perPage','percent','perform','period','periodidx','periodo','perm','permStatus','permalink','permanent','permerror','permission','permissions','perms','perms0','perms1','perms2','perms3','perms4','perms5','perms6','perms7','perms8','perms9','perpage','persist','persistcommonwireless','persistent','person','personId','personal','personality','peruserbw','pf','pfrom','pftext','pg','pgdb','pgport','pgsql','pgsqlcon','pgtId','pgtIou','pguser','phase','phone','phone1','phone2','phone3','phoneNr','phonenumber','photo','photoid','php','phpMyAdmin','phpThumbDebug','php_path','phpbb','phpbbdbh','phpbbdbn','phpbbdbp','phpbbdbu','phpbbkat','phpcode','phpenabled','phperror','phpev','phpexec','phpinfo','phpini','phpsettingid','phpsettings','phpvarname','phrase','pi','piasS','pic','pick','pickfieldcolname','pickfieldlabel','pickfieldname','pickfieldtable','pics','pictitle','picture','pid','pids','pin','ping','pinned','pipe','pipi','pk','pkg','pkgrepourl','pkgs','pl','place','placeID','placeName','placement','plain','plaintext','plan','platform','play','player','playlist','playlistDescription','playlistTitle','plid','plname','plug','plugin','plugins','plus','plusminus','pm','pmid','pmnotif','pms','pmsg','pn','pname','png','pod','point','pointer','points','policies','poll','pollOptions','pollQuestion','pollid','pollport','pollvote','pool','poolname','poolopts','pools','pop','pop3host','popup','popuptitle','popuptype','popupurl','porder','port','port1','portalauth','portbc','portbl','portbw','portscanner','pos','position','post','post1','post2','postData','postId','postRedirect','postafterlogin','postal','postback','postcode','posted','postedText','poster','postfrom','postgroup','postgroups','postid','posts','postsperpage','posttext','postto','posttype','potentalid','potentialid','power','pp','ppage','ppdebug','ppid','pppoeid','ppsflag2','ppsflag3','ppsflag4','ppsfudge1','ppsport','ppsrefid','ppsselect','ppsstratum','pr','pre','preauthurl','precmd','predefined','pref','preference','prefetch','prefetchkey','prefix','prefork','preg','prenom','prepare','prepopulate','prereq','prescription','presence','preset','press','pressthis','pretty','prev','preview','previewed','previewwrite','previous','prevpage','pri','price','priceCurrency','prices','primary','primaryconsole','primarymodule','principal','print','printer','printview','prio','priority','priority1','priority2','priority3','priv','privacy','private','privatekey','privid','privileges','prj','pro','probability','probe','problem','procedure','proceed','process','processed','processing','processlist','processlogin','product','productDescription','productcode','productid','productlist','productname','products','producttype','prof','profile','profileId','profiler','profiles','profiling','prog','program','progress','progresskey','project','projectID','projectid','projection','projectionxy','projects','promiscuous','promote','prop','properties','property','protect','protection','protmode','proto','protocol','protocomp','prov','provider','province','proxy','proxyhost','proxyhostmsg','proxypass','proxypassword','proxyport','proxypwd','proxyurl','proxyuser','proxyusername','prune','pruningOptions','prv','ps','ps2pdf','pseudo','psid','psk','psubmit','pt','ptID','pto','ptp','ptpid','ptype','pu','puT','pub','pubdate','pubkey','public','publicUpload','publickey','publish','published','publisher','publisherID','publisherName','purchaseid','purchaseorderid','puremode','purge','purgedb','purpose','push','pw','pw2','pwd','px','q','q2','q3','qa','qact','qact2','qact3','qaction','qcontent','qid','qindsub','qmrefresh','qq','qqfafile','qqfile','qr','qs','qsubject','qt','qtranslateincompatiblemessage','qty','qtype','qu','quality','quantity','quantityBackup','querY','query','queryPart','queryString','queryType','querysql','querytype','quest','question','questionid','questions','queue','quick','quickReturnID','quicklogin','quickmanager','quickmanagerclose','quickmanagertv','quickmod','quiet','quietlogin','quirks','quitchk','quizid','qunfatmpname','quota','quote','quoteid','qx','r','r00t','r1','r2','r3','r4','rID','rM','rN','race','radPostPage','radio','radiobutton','radius','radiusacctport','radiusenable','radiusip','radiusip2','radiusip3','radiusip4','radiusissueips','radiuskey','radiuskey2','radiuskey3','radiuskey4','radiusnasid','radiusport','radiusport2','radiusport3','radiusport4','radiussecenable','radiussecret','radiussecret2','radiusserver','radiusserver2','radiusserver2acctport','radiusserver2port','radiusserveracctport','radiusserverport','radiusvendor','radns1','radns2','radomainsearchlist','rage','ragename','rainterface','ramode','rand','randkey','random','range','rank','ranking','rapriority','rasamednsasdhcp6','rate','rating','ratings','ratio','raw','rawAuthMessage','rawfilter','rback','rc','rdata','re','read','reading','readme','readonly','readregname','ready','realName','realm','realname','realpath','reason','reasontype','reauth','reauthenticate','reauthenticateacct','reboot','reborrowLimit','rebroadcast','rebuild','rec','recache','recapBy','recaptcha','receipient','receipt','receiver','recent','recherche','recipient','recipientAmount','recipientCurrency','recipients','recommend','reconstruct','record','recordID','recordNum','recordOffset','recordSep','recordType','recordcount','recordid','records','recordsArray','recover','recovered','recoveryPassword','recreate','recsEachPage','recurrence','recurring','recurringtype','recurse','recursive','recvDate','reddi','redfi','redir','redirect','redirectUri','redirection','redirectto','redirurl','ref','reference','referer','referer2','referid','referral','referredby','referrer','refid','refkod','reflectiontimeout','refresh','refreshinterval','refuid','refund','refurl','refuse','reg','regDate','regSubmit','regcountry','regdhcp','regdhcpstatic','regdomain','regenerate','regex','regexp','regid','reginput','region','register','registered','registration','registre','reglocation','regname','regtype','regularity','regval','reinstall','rel','rela','related','relatedmodule','relation','relations','relationship','relationships','relative','relay','relayd','release','releasedate','relevance','relmodule','reload','reloadfilter','relpathinfo','rem','remail','remark','remarks','remdays','remember','rememberMe','rememberme','remhrs','reminder','remipp','remmin','remot','remote','remotefile','remoteip','remotekey','remoteserver','remoteserver2','remoteserver3','remove','removeAll','removeFines','removeID','removeOldVisits','removeVariables','removeall','removefields','removeheader','removeid','removemp','removep','removesess','removewidget','rempool','ren','rename','renameext','renamefile','renamefileto','renamefolder','render','renderfields','renderforms','renderimages','renderlinks','renf','rennew','renold','rensub','reopen','reorder','repair','repass','repassword','repeat','repeatMonth','repeatable','replace','replaceWith','replayMode','replies','reply','replyto','replytocom','repo','repopulate','report','reportContentType','reportType','reportView','reportfun','reportid','reportname','reports','reportsent','repositoryurl','repwd','req','req128','reqFor','reqType','reqid','request','requestKey','requestcompression','requestid','requests','requireAgreement','required','requiredData','res','rescanerrors','rescanwifi','resend','resent','reserveAlert','reserveID','reserveItemID','reserveLimit','reserved','reset','resetPassword','resetVoteCount','resetheader','resetkey','resetlog','resetlogs','resetpass','resetpasskey','resetpassword','resettext','resetwidgets','reshares','residence','resize','resizefile','resizetype','resolution','resolve','resource','resourcefile','resources','response','responsecompression','responsive','respuesta','restart','restartchk','restock','restore','restorearea','restorefile','restrict','resubmit','result','resultXML','resultid','resultmatch','results','resume','resync','ret','retries','retry','return','returnID','returnURL','returnUrl','returnaction','returnpage','returnsession','returnto','returnurl','rev','reveal','reverse','reverseacct','revert','review','revision','revoke','revokeall','rewrite','rf','rfc959workaround','rfile','rfiletxt','richtext','rid','right','rights','rm','rmFiles','rmdir','rmid','rminstall','rmver','rn','rname','robotsnew','rocommunity','role','roleid','rolename','roles','rollback','rollbits','room','root','rootpath','rotate','rotatefile','round','route','routeid','routes','routines','row','rowId','rowid','rownum','rownumber','rows','rowspage','rp','rpassword','rport','rpp','rrdbackup','rrule','rs','rsargs','rsd','rss','rssfeed','rssmaxitems','rssurl','rsswidgetheight','rsswidgettextlength','rstarget1','rstarget2','rstarget3','rstarget4','rt','rtl','rto','rule','ruledef','ruledefgroup','ruleid','rules','ruletype','run','runQuery','runState','runcmd','runer','runid','runsnippet','runtests','rvm','rw','rwcommunity','rwenable','rxantenna','s','s3bucket','s3key','sColumns','sEcho','sID','sName','sSearch','sYear','sa','sabapikeytype','sabsetting','saction','safe','safecss','safefile','safemodz','saleprice','salesrank','salt','salutation','same','sameall','samemix','sample','sampledata','sandbox','sat','save','saveData','saveField','saveKardexes','saveLogs','saveNback','saveNclose','saveNcreate','saveNedit','savePath','saveToFile','saveZ','saveandnext','saveasdraft','saveauthors','saveconf','saved','savedraft','savefile','savefilename','savefilenameurl','savefolder','savefolderurl','savegroup','savehostid','saveid','savemode','savemsg','saveoptions','savepms','savesettings','savetest','savmode','sbjct','sc','sca','scale','scalepoints','scalingup','scan','scdir','scenario','scene','sched','schedule','schedule0','scheduled','schema','scheme','school','schooldatex','scid','scope','score','scores','screen','script','scripts','scrollto','scrubnodf','scrubrnid','sd','sday','sdb','seC','sea','searcc','search','searchClause','searchClause2','searchField','searchId','searchKey','searchName','searchOper','searchQuery','searchString','searchTerm','searchText','searchType','searchUsername','searchable','searchaction','searchadvcat','searchadvgroups','searchadvposter','searchadvr','searchadvsizefrom','searchadvsizeto','searchbox','searchby','searchfield','searchid','searchin','searchip','searchlabel','searchstring','searchterm','searchtext','searchtype','searchuser','searchval','season','sec','second','secret','secretKey','secs','sect','section','sectionid','sections','secu','securesubmit','security','securityscanner','sedir','seed','segment','sel','selCountry','selday','sele','select','selectAmount','selectall','selectcategory','selected','selectedDoc','selectedTable','selectedmodule','selection','selectlist','selectop','selector','selectvalues','sellernick','selmonth','selyear','send','sendTo','sendactivation','sendemail']
        suffix = self.generate_random_string(random.randint(4, 8))
        return random.choice(prefixes) + suffix

    def generate_varied_content(self, size):
        return self.generate_random_string(size, string.ascii_letters + string.digits)

    def generate_urlencoded_content(self, size):
        return self.generate_random_string(size, string.ascii_letters + string.digits)

    def _bytes_to_ascii(self, data):
        return ''.join(chr(b & 0xFF) for b in data)

    def _is_json_lines_content_type(self, raw_content_type):
        return raw_content_type in (
            "application/ndjson",
            "application/x-ndjson",
            "application/jsonlines",
            "application/x-jsonlines",
            "application/jsonl",
            "application/x-jsonl",
            "text/ndjson",
            "text/x-ndjson",
            "text/jsonlines",
            "text/x-jsonlines",
            "text/jsonl",
            "text/x-jsonl",
        )

    def _find_first_non_ws(self, data, start, end):
        whitespace = set([0x20, 0x09, 0x0a, 0x0d])
        i = start
        while i < end and (data[i] & 0xFF) in whitespace:
            i += 1
        return i

    def _find_last_non_ws(self, data, start, end):
        whitespace = set([0x20, 0x09, 0x0a, 0x0d])
        i = end - 1
        while i >= start and (data[i] & 0xFF) in whitespace:
            i -= 1
        return i

    def _generate_xml_comment_content(self, length):
        if length <= 0:
            return ""
        return self.generate_random_string(length, string.ascii_letters + string.digits)

    def _get_raw_content_type(self, request_info):
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                value = header.split(":", 1)[1].strip().lower()
                return value.split(";", 1)[0].strip()
        return ""

    def _is_supported_content_type(self, request_info):
        content_type = request_info.getContentType()
        if content_type in (
            IRequestInfo.CONTENT_TYPE_URL_ENCODED,
            IRequestInfo.CONTENT_TYPE_XML,
            IRequestInfo.CONTENT_TYPE_JSON,
            IRequestInfo.CONTENT_TYPE_MULTIPART,
        ):
            return True
        raw_content_type = self._get_raw_content_type(request_info)
        if raw_content_type == "text/plain":
            return True
        if self._is_json_lines_content_type(raw_content_type):
            return True
        if raw_content_type in ("application/graphql", "application/x-graphql", "text/graphql"):
            return True
        if raw_content_type in ("application/x-yaml", "text/yaml", "text/x-yaml", "application/yaml"):
            return True
        if raw_content_type in ("text/csv", "application/csv"):
            return True
        return False

    def _build_comment_junk(self, size, prefix):
        if size <= len(prefix):
            return prefix[:size]
        return prefix + self.generate_varied_content(size - len(prefix))

    def _build_line_comment(self, size_bytes, prefix, suffix):
        content_len = size_bytes - len(prefix) - len(suffix)
        if content_len < 0:
            content_len = 0
        return prefix + self.generate_varied_content(content_len) + suffix

    def _build_csv_junk(self, size_bytes):
        num_columns = random.randint(3, 8)
        row_template_len = num_columns + 1
        content_per_col = (size_bytes - row_template_len) // num_columns
        if content_per_col < 1:
            content_per_col = 1
        columns = [self.generate_varied_content(content_per_col) for _ in range(num_columns)]
        return ','.join(columns) + '\n'

    def _build_xml_comment(self, size_bytes):
        content_len = size_bytes - 7
        if content_len < 0:
            content_len = 0
        return "<!--{}-->".format(self._generate_xml_comment_content(content_len))

    def _build_urlencoded_junk(self, size_bytes, prefix, suffix):
        param_name = self.generate_random_param()
        overhead = len(prefix) + len(param_name) + len(suffix) + 1
        value_len = size_bytes - overhead
        if value_len < 0:
            value_len = 0
        return prefix + param_name + "=" + self.generate_urlencoded_content(value_len) + suffix

    def _get_multipart_boundary(self, request_info):
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', header, re.I)
                if match:
                    return (match.group(1) or match.group(2)).strip()
        return None

    def _create_multipart_junk(self, boundary, size):
        if not boundary:
            return None

        junk_field_name = self.generate_random_param()
        multipart_structure = (
            "--{0}\r\n"
            "Content-Disposition: form-data; name=\"{1}\"\r\n\r\n"
            "{2}\r\n"
        )

        structure_size = len(multipart_structure.format(boundary, junk_field_name, ""))
        content_len = size - structure_size
        if content_len < 0:
            content_len = 0
        junk_data = self.generate_varied_content(content_len)
        return multipart_structure.format(boundary, junk_field_name, junk_data)

    def _find_sequence(self, data, seq, start):
        data_len = len(data)
        seq_len = len(seq)
        if seq_len == 0 or data_len < seq_len:
            return -1
        i = start
        end = data_len - seq_len
        while i <= end:
            match = True
            for j in range(seq_len):
                if (data[i + j] & 0xFF) != seq[j]:
                    match = False
                    break
            if match:
                return i
            i += 1
        return -1

    def _find_multipart_start(self, request, request_info):
        boundary = self._get_multipart_boundary(request_info)
        if not boundary:
            return None
        body_offset = request_info.getBodyOffset()
        opening = "--" + boundary
        seq = [ord(ch) for ch in opening]
        index = self._find_sequence(request, seq, body_offset)
        if index == -1:
            return None
        return index

    def _find_multipart_insertion_point(self, request, request_info):
        boundary = self._get_multipart_boundary(request_info)
        if not boundary:
            return None
        body_offset = request_info.getBodyOffset()
        closing = "--" + boundary + "--"
        seq = [ord(ch) for ch in closing]
        index = self._rfind_sequence(request, seq, body_offset)
        if index == -1:
            return None
        return index

    def _rfind_sequence(self, data, seq, start):
        data_len = len(data)
        seq_len = len(seq)
        if seq_len == 0 or data_len < seq_len:
            return -1
        i = data_len - seq_len
        if i < start:
            return -1
        while i >= start:
            match = True
            for j in range(seq_len):
                if (data[i + j] & 0xFF) != seq[j]:
                    match = False
                    break
            if match:
                return i
            i -= 1
        return -1

    def _get_xml_insertion_point(self, request, request_info):
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]
        whitespace = set([0x20, 0x09, 0x0a, 0x0d])
        start = 0
        if len(body) >= 3:
            if (body[0] & 0xFF) == 0xEF and (body[1] & 0xFF) == 0xBB and (body[2] & 0xFF) == 0xBF:
                start = 3
        while start < len(body) and (body[start] & 0xFF) in whitespace:
            start += 1
        if start >= len(body):
            return body_offset + start
        if not self._matches_ascii_ci(body, start, "<?xml"):
            return body_offset + start
        end = self._find_xml_decl_end(body, start + 5)
        if end is None:
            return body_offset + start
        return body_offset + end + 2

    def _matches_ascii_ci(self, data, start, needle):
        if start + len(needle) > len(data):
            return False
        for i, ch in enumerate(needle):
            b = data[start + i] & 0xFF
            if 65 <= b <= 90:
                b += 32
            if b != ord(ch):
                return False
        return True

    def _find_xml_decl_end(self, data, start):
        end = len(data) - 1
        i = start
        while i < end:
            if (data[i] & 0xFF) == ord('?') and (data[i + 1] & 0xFF) == ord('>'):
                return i
            i += 1
        return None

    def _update_content_length(self, request):
        request_info = self._helpers.analyzeRequest(request)
        headers = list(request_info.getHeaders())
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]
        body_len = len(body)

        has_chunked = False
        new_headers = []
        for header in headers:
            lower = header.lower()
            if lower.startswith("transfer-encoding:") and "chunked" in lower:
                has_chunked = True
            if lower.startswith("content-length:"):
                continue
            new_headers.append(header)

        if not has_chunked:
            if len(new_headers) > 1:
                new_headers.insert(1, "Content-Length: " + str(body_len))
            else:
                new_headers.append("Content-Length: " + str(body_len))

        return self._helpers.buildHttpMessage(new_headers, body)

    def _is_chunked(self, request_info):
        headers = request_info.getHeaders()
        for header in headers:
            lower = header.lower()
            if lower.startswith("transfer-encoding:") and "chunked" in lower:
                return True
        return False

    def _get_urlencoded_prefix(self, request, request_info, insertion_point):
        body_offset = request_info.getBodyOffset()
        if insertion_point != len(request):
            return ""
        if len(request) <= body_offset:
            return ""
        if len(request) == body_offset:
            return ""
        if request[-1] != ord('&'):
            return "&"
        return ""

    def _insert_junk(self, request, insertion_point, junk_data):
        baos = ByteArrayOutputStream()
        baos.write(request[:insertion_point])
        baos.write(junk_data.encode('utf-8'))
        baos.write(request[insertion_point:])
        return baos.toByteArray()

    def _build_junk_data(self, request, request_info, size_bytes):
        content_type = request_info.getContentType()
        raw_content_type = self._get_raw_content_type(request_info)

        if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
            return self._build_urlencoded_junk(size_bytes, "", "&")

        if content_type == IRequestInfo.CONTENT_TYPE_XML:
            return self._build_xml_comment(size_bytes)

        if content_type == IRequestInfo.CONTENT_TYPE_JSON:
            param_name = self.generate_random_param()
            value_len = size_bytes - len(param_name) - 5
            if value_len < 0:
                value_len = 0
            return '"{}":"{}",'.format(param_name, self.generate_varied_content(value_len))

        if content_type == IRequestInfo.CONTENT_TYPE_MULTIPART:
            boundary = self._get_multipart_boundary(request_info)
            return self._create_multipart_junk(boundary, size_bytes)

        if raw_content_type == "text/plain":
            return self.generate_varied_content(size_bytes)

        if raw_content_type in ("application/graphql", "application/x-graphql", "text/graphql"):
            return self._build_comment_junk(size_bytes, "\n# ")

        if raw_content_type in ("application/x-yaml", "text/yaml", "text/x-yaml", "application/yaml"):
            return self._build_comment_junk(size_bytes, "\n# ")

        if raw_content_type in ("text/csv", "application/csv"):
            return self._build_csv_junk(size_bytes)

        return None

    def _build_auto_inject_payload(self, request, request_info, size_bytes):
        raw_content_type = self._get_raw_content_type(request_info)
        if self._is_json_lines_content_type(raw_content_type):
            return self._build_auto_json_lines_payload(request, request_info, size_bytes)

        content_type = request_info.getContentType()
        if content_type == IRequestInfo.CONTENT_TYPE_JSON:
            return self._build_auto_json_payload(request, request_info, size_bytes)

        if content_type == IRequestInfo.CONTENT_TYPE_MULTIPART:
            return self._build_auto_multipart_payload(request, request_info, size_bytes)

        if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
            return self._build_auto_urlencoded_payload(request, request_info, size_bytes)

        if content_type == IRequestInfo.CONTENT_TYPE_XML:
            insertion_point = self._get_xml_insertion_point(request, request_info)
            junk_data = self._build_xml_comment(size_bytes)
            return insertion_point, junk_data

        if raw_content_type == "text/plain":
            return request_info.getBodyOffset(), self.generate_varied_content(size_bytes)

        if raw_content_type in ("application/graphql", "application/x-graphql", "text/graphql"):
            return request_info.getBodyOffset(), self._build_line_comment(size_bytes, "# ", "\n")

        if raw_content_type in ("application/x-yaml", "text/yaml", "text/x-yaml", "application/yaml"):
            return request_info.getBodyOffset(), self._build_line_comment(size_bytes, "# ", "\n")

        if raw_content_type in ("text/csv", "application/csv"):
            return request_info.getBodyOffset(), self._build_csv_junk(size_bytes)

        return None, None

    def _build_auto_urlencoded_payload(self, request, request_info, size_bytes):
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]
        suffix = "&" if len(body) > 0 else ""
        junk_data = self._build_urlencoded_junk(size_bytes, "", suffix)
        return request_info.getBodyOffset(), junk_data

    def _build_auto_multipart_payload(self, request, request_info, size_bytes):
        insertion_point = self._find_multipart_start(request, request_info)
        if insertion_point is None:
            insertion_point = request_info.getBodyOffset()
        boundary = self._get_multipart_boundary(request_info)
        junk_data = self._create_multipart_junk(boundary, size_bytes)
        if not junk_data:
            return None, None
        return insertion_point, junk_data

    def _build_auto_json_lines_payload(self, request, request_info, size_bytes):
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]
        if not body:
            return None, None

        start = 0
        if len(body) >= 3:
            if (body[0] & 0xFF) == 0xEF and (body[1] & 0xFF) == 0xBB and (body[2] & 0xFF) == 0xBF:
                start = 3

        i = start
        while i < len(body):
            line_start = i
            line_end = i
            while line_end < len(body) and (body[line_end] & 0xFF) not in (0x0a, 0x0d):
                line_end += 1

            value_start = self._find_first_non_ws(body, line_start, line_end)
            if value_start < line_end:
                value_end = self._find_last_non_ws(body, value_start, line_end)
                if value_end < value_start:
                    return None, None
                first_char = body[value_start] & 0xFF
                last_char = body[value_end] & 0xFF
                if first_char == ord('{') and last_char == ord('}'):
                    return self._build_auto_json_object_payload(body_offset, body, value_start, value_end, size_bytes)
                if first_char == ord('[') and last_char == ord(']'):
                    return self._build_auto_json_array_payload(body_offset, body, value_start, value_end, size_bytes)
                return None, None

            i = line_end
            while i < len(body) and (body[i] & 0xFF) in (0x0a, 0x0d):
                i += 1

        return None, None

    def _build_auto_json_payload(self, request, request_info, size_bytes):
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]

        start = 0
        if len(body) >= 3:
            if (body[0] & 0xFF) == 0xEF and (body[1] & 0xFF) == 0xBB and (body[2] & 0xFF) == 0xBF:
                start = 3

        start = self._find_first_non_ws(body, start, len(body))
        end = self._find_last_non_ws(body, start, len(body))
        if end < start:
            return None, None

        first_char = body[start] & 0xFF
        last_char = body[end] & 0xFF
        if first_char == ord('{') and last_char == ord('}'):
            return self._build_auto_json_object_payload(body_offset, body, start, end, size_bytes)
        if first_char == ord('[') and last_char == ord(']'):
            return self._build_auto_json_array_payload(body_offset, body, start, end, size_bytes)
        return None, None

    def _build_auto_json_object_payload(self, body_offset, body, start, end, size_bytes):
        content_start = start + 1
        first_non_ws = self._find_first_non_ws(body, content_start, end)
        is_empty = first_non_ws >= end

        indent_bytes = body[content_start:first_non_ws] if first_non_ws > content_start else []
        indent = self._bytes_to_ascii(indent_bytes)
        suffix = ""
        if is_empty:
            if indent:
                suffix = indent
        else:
            suffix = "," + indent

        param_name = self.generate_random_param()
        overhead = 5 + len(suffix)
        value_len = size_bytes - len(param_name) - overhead
        if value_len < 0:
            value_len = 0

        junk_field = '"{}":"{}"'.format(param_name, self.generate_varied_content(value_len)) + suffix

        insertion_point = body_offset + first_non_ws
        return insertion_point, junk_field

    def _build_auto_json_array_payload(self, body_offset, body, start, end, size_bytes):
        content_start = start + 1
        first_non_ws = self._find_first_non_ws(body, content_start, end)
        is_empty = first_non_ws >= end
        indent_bytes = body[content_start:first_non_ws] if first_non_ws > content_start else []
        indent = self._bytes_to_ascii(indent_bytes)
        suffix = ""
        if is_empty:
            if indent:
                suffix = indent
        else:
            suffix = "," + indent

        overhead = 2 + len(suffix)
        value_len = size_bytes - overhead
        if value_len < 0:
            value_len = 0

        junk_element = '"' + self.generate_varied_content(value_len) + '"' + suffix

        insertion_point = body_offset + first_non_ws
        return insertion_point, junk_element

    def insert_random_data(self, event):
        try:
            message = self.context.getSelectedMessages()[0]
            request = message.getRequest()
            selection_bounds = self.context.getSelectionBounds()

            options_panel = JPanel()
            options_panel.setLayout(swing.BoxLayout(options_panel, swing.BoxLayout.Y_AXIS))

            junk_sizes_kb = [8, 16, 32, 64, 128, 150, 1024, "Custom"]
            dropdown = swing.JComboBox([str(size) + " KB" if isinstance(size, int) else size for size in junk_sizes_kb])
            
            custom_size_field = JTextField(10)
            custom_size_label = JLabel("Custom size (bytes):")

            custom_size_field.setVisible(dropdown.getSelectedItem() == "Custom")
            custom_size_label.setVisible(dropdown.getSelectedItem() == "Custom")

            options_panel.add(dropdown)
            options_panel.add(custom_size_label)
            options_panel.add(custom_size_field)

            def update_custom_field_visibility(event):
                is_custom_selected = dropdown.getSelectedItem() == "Custom"
                custom_size_label.setVisible(is_custom_selected)
                custom_size_field.setVisible(is_custom_selected)
                if is_custom_selected:
                    custom_size_field.requestFocus()
                swing.SwingUtilities.getWindowAncestor(options_panel).pack()

            dropdown.addActionListener(update_custom_field_visibility)

            frame = JFrame()
            dialog = JOptionPane.showConfirmDialog(frame, options_panel, "Select Junk Data Size", 
                                                 JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            
            if dialog == JOptionPane.OK_OPTION:
                selected_size = dropdown.getSelectedItem()
                if selected_size == "Custom":
                    try:
                        size_bytes = int(custom_size_field.getText())
                    except ValueError:
                        JOptionPane.showMessageDialog(None, "Please enter a valid number for custom size.")
                        return
                    if size_bytes <= 0:
                        JOptionPane.showMessageDialog(None, "Custom size must be a positive number (bytes).")
                        return
                else:
                    size_bytes = int(selected_size.split()[0]) * 1024

                request_info = self._helpers.analyzeRequest(message)
                self._maybe_log_missing_content_type(request, request_info)
                if self._is_chunked(request_info):
                    JOptionPane.showMessageDialog(None, "Chunked requests are not supported for manual inject.")
                    return
                content_type = request_info.getContentType()

                if selection_bounds is None:
                    insertion_point, junk_data = self._build_auto_inject_payload(request, request_info, size_bytes)
                    if not junk_data:
                        JOptionPane.showMessageDialog(
                            None,
                            "Unsupported content type for automatic placement. Select an insertion point manually."
                        )
                        return
                else:
                    insertion_point = selection_bounds[0]
                    if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                        prefix = self._get_urlencoded_prefix(request, request_info, insertion_point)
                        junk_data = self._build_urlencoded_junk(size_bytes, prefix, "&")
                    else:
                        junk_data = self._build_junk_data(request, request_info, size_bytes)
                if not junk_data:
                    return

                new_request = self._insert_junk(request, insertion_point, junk_data)
                message.setRequest(self._update_content_length(new_request))
                self._mark_junk_comment(message)
        except Exception:
            self._log_error("insert_random_data")
            self._alert_error("insert_random_data", rate_limit=False)
            JOptionPane.showMessageDialog(None, "Error injecting junk data. Check Burp Extender output.")

    def toggle_auto_inject(self, event):
        self._auto_inject_enabled = not self._auto_inject_enabled
        self._callbacks.saveExtensionSetting(
            "auto_inject_enabled",
            "true" if self._auto_inject_enabled else "false"
        )

    def set_auto_inject_size(self, event):
        prompt = "Auto-inject size (KB):"
        value = JOptionPane.showInputDialog(None, prompt, str(self._auto_inject_kb))
        if value is None:
            return
        try:
            size_kb = int(value)
            if size_kb <= 0:
                raise ValueError()
        except ValueError:
            JOptionPane.showMessageDialog(None, "Please enter a positive integer (KB).")
            return
        self._auto_inject_kb = size_kb
        self._callbacks.saveExtensionSetting("auto_inject_kb", str(size_kb))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self._auto_inject_enabled:
                return
            if not messageIsRequest:
                return
            if toolFlag != self._callbacks.TOOL_SCANNER:
                return

            request = messageInfo.getRequest()
            request_info = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)
            self._maybe_log_missing_content_type(request, request_info)
            if self._is_chunked(request_info):
                return
            body_offset = request_info.getBodyOffset()
            if body_offset >= len(request):
                return

            size_bytes = self._auto_inject_kb * 1024
            insertion_point, junk_data = self._build_auto_inject_payload(request, request_info, size_bytes)
            if not junk_data:
                return

            new_request = self._insert_junk(request, insertion_point, junk_data)
            messageInfo.setRequest(self._update_content_length(new_request))
            self._mark_junk_comment(messageInfo)
        except Exception:
            self._log_error("processHttpMessage")
            self._alert_error("processHttpMessage")

    def create_multipart_junk(self, request, size):
        request_info = self._helpers.analyzeRequest(request)
        boundary = self._get_multipart_boundary(request_info)
        return self._create_multipart_junk(boundary, size)
