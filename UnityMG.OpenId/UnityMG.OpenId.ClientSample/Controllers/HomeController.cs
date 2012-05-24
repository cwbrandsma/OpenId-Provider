using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace UnityMG.OpenId.ClientSample.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            if (Request.Headers["Accept"].Contains("xrds"))
                return View("Xrds");

            Response.AppendHeader(
                "X-XRDS-Location",
                new Uri(Request.Url, Response.ApplyAppPathModifier("~/Home/xrds")).AbsoluteUri);



            ViewBag.Message = "Welcome to ASP.NET MVC!";

            return View();
        }

        public ActionResult About()
        {
            return View();
        }

        public ActionResult Xrds()
        {
            return View();
        }
    }
}
