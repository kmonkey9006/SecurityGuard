using Common.Logger;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace SecurityGuard
{
    public enum SecurityGuard
    {
        None = 0,
        LogTrace = 1,
        HotLinking = 2,
        Attacking = 4,
        NewSession = 8,
        AjaxRequest = 16,
        Uploading = 32,
        All = LogTrace | HotLinking | Attacking | NewSession | AjaxRequest | Uploading
    }

    public class NeedSecurityGuardAttribute : ActionFilterAttribute
    {
        static NeedSecurityGuardAttribute()
        {
            _avoidattacker.Init("IPAttackingAvoidMaxPendingTimes");
        }

        SecurityGuard _sg = SecurityGuard.None;
        string _extnames = "", _denyextnames = ".exe|.bat|msi|.vbs|.js|.cmd|.src|.reg|.com|.lnk|.pif|.dll|.drv|.fon|.jar|.css|.asp|.aspx|.jsp|.html|.stm|.axd|.vbhtml|.cshtml|.asmx|.aspq|.cshtm|.vbhtm|.rem|.soap|.cer|.ashx|.shtm|.sthml";

        public SecurityGuard SG { get { return _sg; } }
        public NeedSecurityGuardAttribute(SecurityGuard sg = SecurityGuard.None, string extnames = ".ico|.jpg|.gif|.png|.doc|.docx|.xls|.xlsx|.ppt|.ppts|.pps|.txt|.zip|.rar")
           
        {
            _sg = sg;
            _extnames = extnames;
        }
        static List<string> allowedextnames = new List<string>();
        static List<string> denyextnames = new List<string>();
        static AvoidIPAttacker _avoidattacker = new AvoidIPAttacker();
        public static List<string> AllowedAuthorities = new List<string>();
        static bool hotlinker_inited = false;
        static bool upload_inited = false;
        ILogger logger = new Logger4Net("JobServer");
        public bool IsHotLinking(string authority)
        {
            if (!hotlinker_inited)
            {
                if (AllowedAuthorities.Count == 0)
                {
                    var ads = ConfigurationManager.AppSettings["SecurityGuard_AllowedDomain"];
                    if (!string.IsNullOrWhiteSpace(ads))
                    {
                        AllowedAuthorities.AddRange(ads.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
                    }
                    AllowedAuthorities.Add("localhost");
                }
                hotlinker_inited = true;
            }
            return !AllowedAuthorities.Contains(authority);
        }


        bool IsHotLinking(HttpRequestBase request)
        {
            if (!IsHotLinking(request.Url.DnsSafeHost)) return false;
            return request.UrlReferrer == null;
            //return IsHotLinking(request.Url.DnsSafeHost);
        }
        bool IsNewSession(HttpContextBase request)
        {
            return request.Session.IsNewSession;
        }
        bool IsAjaxRequest(HttpRequestBase request)
        {
            return request.IsAjaxRequest();
        }

        bool IsAttacking(HttpRequestBase request)
        {
            return _avoidattacker.Attacking(request.GetIP());
        }
        bool DenyUploading(HttpRequestBase request)
        {
            if (!upload_inited)
            {
                denyextnames.AddRange(_denyextnames.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
            }
            allowedextnames.AddRange(_extnames.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
            bool deny = true;
            foreach (var key in request.Files.AllKeys)
            {
                if (denyextnames.Count > 0)
                {
                    if (denyextnames.Any(n => request.Files[key].FileName.EndsWith(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        deny = true;
                        break;
                    }
                }
                if (allowedextnames.Count > 0)
                {
                    if (allowedextnames.Any(n => request.Files[key].FileName.EndsWith(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        deny = false;
                        continue;
                    }
                }
            }
            return deny;
        }
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            //base.OnActionExecuting(filterContext);
            //return;
            if (filterContext.IsChildAction) return;
            bool refuse = false;
            string msg = null;
            if ((SG & SecurityGuard.HotLinking) == SecurityGuard.HotLinking)
            {
                refuse = refuse || IsHotLinking(filterContext.HttpContext.Request);
                if (refuse)
                    msg = " 盗链可耻";
            }
            if ((SG & SecurityGuard.NewSession) == SecurityGuard.NewSession)
            {
                refuse = refuse || IsNewSession(filterContext.HttpContext);
                if (refuse)
                    msg = " 被中断";
            }
            if ((SG & SecurityGuard.AjaxRequest) == SecurityGuard.AjaxRequest)
            {
                refuse = refuse || IsAjaxRequest(filterContext.HttpContext.Request);
                if (refuse)
                    msg = " 被禁止";
            }
            if ((SG & SecurityGuard.Attacking) == SecurityGuard.Attacking)
            {
                refuse = refuse || IsAttacking(filterContext.HttpContext.Request);
                if (refuse)
                    msg = " 被拒绝";
            }
            if ((SG & SecurityGuard.Uploading) == SecurityGuard.Uploading)
            {
                refuse = refuse || DenyUploading(filterContext.HttpContext.Request);
                if (refuse)
                    msg = " 禁止上传";
            }
            if ((SG & SecurityGuard.LogTrace) == SecurityGuard.LogTrace || refuse)
                logger.Trace("URL:" + filterContext.HttpContext.Request.Url.OriginalString + msg + filterContext.HttpContext.Info());
            if (!refuse) return;

            //filterContext.HttpContext.Response.Redirect("www.google.com");
            filterContext.HttpContext.Response.Write(msg);
            filterContext.HttpContext.Response.End();
            filterContext.HttpContext.Response.Close();
            //filterContext.HttpContext.Session.Timeout = 0;
            filterContext.HttpContext.Session.Abandon();
            var result = new ContentResult() { Content = msg };
            result.Content = msg;
            filterContext.Result = result;
            //filterContext.HttpContext.Response.Redirect("/");
        }

    }

    internal static class ext
    {

        public static string Info(this HttpContextBase context)
        {
            StringBuilder sb = new StringBuilder();
            HttpBrowserCapabilitiesBase bc = context.Request.Browser;
            sb.AppendLine();
            sb.AppendLine("=====Browser Capabilities:=====");
            sb.AppendLine("Type = " + bc.Type);
            sb.AppendLine("Version = " + bc.Version);
            sb.AppendLine("MobileDeviceManufacturer = " + bc.MobileDeviceManufacturer);
            sb.AppendLine("MobileDeviceModel = " + bc.MobileDeviceModel);
            sb.AppendLine("=====LogonUserIdentity:=====");
            sb.AppendLine("IsAuthenticated: " + context.Request.LogonUserIdentity.IsAuthenticated);
            sb.AppendLine("User: " + context.Request.LogonUserIdentity.User);
            sb.AppendLine("Name: " + context.Request.LogonUserIdentity.Name);
            sb.AppendLine("Token: " + context.Request.LogonUserIdentity.Token);
            sb.AppendLine("=====User:=====");
            sb.AppendLine("IP: " + context.Request.GetIP());
            sb.AppendLine("UserAgent: " + context.Request.UserAgent);
            sb.AppendLine("UserHostAddress: " + context.Request.UserHostAddress);
            sb.AppendLine("UserHostName: " + context.Request.UserHostName);

            sb.AppendLine("=====Params:=====");
            sb.AppendLine("LOCAL_ADDR: " + context.Request.Params["LOCAL_ADDR"]);
            sb.AppendLine("REMOTE_ADDR: " + context.Request.Params["REMOTE_ADDR"]);
            sb.AppendLine("REMOTE_HOST: " + context.Request.Params["REMOTE_HOST"]);
            sb.AppendLine("REMOTE_PORT: " + context.Request.Params["REMOTE_PORT"]);
            sb.AppendLine("REQUEST_METHOD: " + context.Request.HttpMethod);
            sb.AppendLine("IsAjaxRequest: " + context.Request.IsAjaxRequest());


            // Write user info to log
            sb.AppendLine("=====Form:=====");
            foreach (var key in context.Request.Form.AllKeys)
            {
                sb.AppendLine(key + ": " + context.Request.Params[key]);
            }
            sb.AppendLine("=====QueryString:=====");
            foreach (var key in context.Request.QueryString.AllKeys)
            {
                sb.AppendLine(key + ": " + context.Request.Params[key]);
            }
            sb.AppendLine("=====Files:=====");
            foreach (var key in context.Request.Files.AllKeys)
            {
                sb.AppendFormat("{0},{1},{2}", key, context.Request.Files[key].FileName, context.Request.Files[key].ContentLength);
            }
            // sb.AppendLine();
            // Write user info to log
            //sb.AppendLine("=====Headers:=====");
            //foreach (var key in context.Request.Headers.AllKeys)
            //{
            //    sb.AppendLine(key + ": " + context.Request.Headers[key]);
            //}
            return sb.ToString();
        }

        internal static string GetIP(this HttpRequestBase request)
        {
            #region getIp
            // 穿过代理服务器取远程用户真实IP地址
            string Ip = string.Empty;
            if (request.ServerVariables["HTTP_VIA"] != null)
            {
                if (request.ServerVariables["HTTP_X_FORWARDED_FOR"] == null)
                {
                    if (request.ServerVariables["HTTP_CLIENT_IP"] != null)
                        Ip = request.ServerVariables["HTTP_CLIENT_IP"].ToString();
                    else
                        if (request.ServerVariables["REMOTE_ADDR"] != null)
                        Ip = request.ServerVariables["REMOTE_ADDR"].ToString();
                    else
                        Ip = "127.0.0.1";
                }
                else
                    Ip = request.ServerVariables["HTTP_X_FORWARDED_FOR"].ToString();
            }
            else if (request.ServerVariables["REMOTE_ADDR"] != null)
            {
                Ip = request.ServerVariables["REMOTE_ADDR"].ToString();
            }
            else
            {
                Ip = "127.0.0.1";
            }
            return Ip;
            #endregion
        }
    }
}
