package com.codemanic.kindi;

import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Text;

import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.PreparedQuery;
import com.google.appengine.api.datastore.Query;
import com.google.appengine.api.datastore.FetchOptions;

import com.google.appengine.api.oauth.InvalidOAuthParametersException;
import com.google.appengine.api.oauth.InvalidOAuthTokenException;
import com.google.appengine.api.oauth.OAuthRequestException;
import com.google.appengine.api.oauth.OAuthService;
import com.google.appengine.api.oauth.OAuthServiceFactory;
import com.google.appengine.api.oauth.OAuthServiceFailureException;
import com.google.appengine.api.users.User;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.io.BufferedReader;
import java.util.*;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CertServlet extends HttpServlet {

  private static final Logger logger = Logger.getLogger(CertServlet.class.getName());

  @Override
  public void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
    JsonObject output = new JsonObject();
    try {
      OAuthService oauthService = OAuthServiceFactory.getOAuthService();
      User user = oauthService.getCurrentUser();
      if (user != null && "POST".equals(req.getMethod()) && "application/x-pem-file".equals(req.getContentType())) {
	  BufferedReader reader = req.getReader();
	  StringBuffer sb = new StringBuffer();
	  int c = reader.read();
	  while (c != -1) {
	      sb.append((char)c);
	      c = reader.read();
	  }

	  Key userKey = KeyFactory.createKey("UserKey", user.getEmail());
	  Date date = new Date();
	  Entity cert = new Entity("Cert", userKey);
	  cert.setProperty("user", user);
	  cert.setProperty("date", date);
	  cert.setProperty("content", new Text(sb.toString()));
	  DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
	  datastore.put(cert);
      } else {
	  String targetEmail = user != null ? user.getEmail() : null;
	  String[] targetEmails = getParameterMap(req).get("email");
	  if (targetEmails != null && targetEmails.length > 0) {
	      targetEmail = targetEmails[0];
	  }
	  if (targetEmail != null) {
	      Key userKey = KeyFactory.createKey("UserKey", targetEmail);
	      Query query = new Query("Cert", userKey).addSort("date", Query.SortDirection.DESCENDING);
	      DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
	      List<Entity> certs = datastore.prepare(query).asList(FetchOptions.Builder.withLimit(5));
	      if (certs.size() > 0) {
		  output.addProperty("cert", ((Text) certs.get(0).getProperty("content")).getValue());
	      }
	  }
      }
      res.setStatus(HttpServletResponse.SC_OK);
      logger.log(Level.INFO, "valid request on behalf of " + user.getEmail());
    } catch (InvalidOAuthTokenException e) {
      res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      output.addProperty("status", "invalid token");
      logger.log(Level.INFO, "request validation failure", e);
    } catch (InvalidOAuthParametersException e) {
      res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      output.addProperty("status", "invalid parameters");
      logger.log(Level.INFO, "request contained invalid token", e);
    } catch (OAuthRequestException e) {
      res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      output.addProperty("status", "bad request");
      logger.log(Level.INFO, "request validation failure", e);
    } catch (OAuthServiceFailureException e) {
      res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      output.addProperty("status", "unexpected error");
      logger.log(Level.INFO, "request validation failure", e);
    }
    res.setHeader("Content-Type", "application/json");
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    res.getWriter().write(gson.toJson(output));
  }
    
  @SuppressWarnings("unchecked")
  Map<String, String[]> getParameterMap(HttpServletRequest req) {
    return req.getParameterMap();
  }
}
