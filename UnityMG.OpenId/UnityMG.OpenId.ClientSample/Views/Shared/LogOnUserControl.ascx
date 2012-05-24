<%@ Control Language="C#" Inherits="System.Web.Mvc.ViewUserControl" %>
<%
    if (Request.IsAuthenticated) {
%>
        Welcome <strong><%: Page.User.Identity.Name %></strong>!
        [ 					<%= Html.ActionLink("Member Area", "Index", "User")%>]
<%
    }
    else {
%> 
        [ 					<%= Html.ActionLink("Member Area", "Index", "User")%> ]
<%
    }
%>
