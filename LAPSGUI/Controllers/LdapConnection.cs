﻿using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using LAPSAPI.Models;
using NLog;

namespace LAPSAPI
{
    public class LdapConnection
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();
        private string ServerHostname;
        private string BaseContext;
        private string BindUsername;
        private string BindPassword;

        public LdapConnection(string LDAPServerHostname, string LDAPBaseContext, string LDAPBindPassword, string LDAPBindUsername)
        {
            ServerHostname = LDAPServerHostname;
            BaseContext = LDAPBaseContext;
            BindUsername = LDAPBindUsername;
            BindPassword = LDAPBindPassword;
        }

        public PrincipalContext GetLdapPrincipalContext() => new PrincipalContext(ContextType.Domain, ServerHostname, BaseContext, ContextOptions.Negotiate, BindUsername, BindPassword);

        private Principal SearchForComputer(string computerName)
        {
            ComputerPrincipal computerQuery = new ComputerPrincipal(GetLdapPrincipalContext());
            computerQuery.Name = computerName;

            PrincipalSearcher searchForComputer = new PrincipalSearcher(computerQuery);
            Principal searchResult = searchForComputer.FindOne();
            
            if (searchResult != null)
            {
                return searchResult;
            }

            throw new ObjectNotFoundException("Could not find computer with name: " + computerName);
        }

        public Credential GetLocalAdminPassword(string computerName)
        {
            Credential result = new Credential();
            Principal searchResult = null;

            try
            {
                searchResult = SearchForComputer(computerName);
            }

            catch (Exception ex)
            {
                throw ex;
            }

            if (searchResult != null)
            {
                DirectoryEntry underlyingComputer = searchResult.GetUnderlyingObject() as DirectoryEntry;
                result.Password = underlyingComputer.Properties["ms-MCS-AdmPwd"].Value as string;
                result.ComputerName = computerName;

                return result;
            }

            return result;
        }

        public ExpirationDateUTC GetLocalAdminExpirationDateUTC(string computerName)
        {
            ExpirationDateUTC result = new ExpirationDateUTC();
            result.ComputerName = computerName;
            Principal searchResult = null;

            try
            {
                searchResult = SearchForComputer(computerName);
            }

            catch (Exception ex)
            {
                throw ex;
            }

            DirectoryEntry underlyingComputer = searchResult.GetUnderlyingObject() as DirectoryEntry;
            string attributeAsString = underlyingComputer.Properties["ms-MCS-AdmPwdExpirationTime"].Value as string;

            result.ExpirationDate = DateTime.FromFileTimeUtc(Convert.ToInt64(attributeAsString)).ToString();

            return result;
        }

        public PasswordHistory GetLocalAdminPasswordHistory(string computerName)
        {
            PasswordHistory result = new PasswordHistory();
            result.ComputerName = computerName;
            Principal searchResult = null;

            try
            {
                searchResult = SearchForComputer(computerName);
            }

            catch (Exception ex)
            {
                throw ex;
            }

            DirectoryEntry underlyingComputer = searchResult.GetUnderlyingObject() as DirectoryEntry;
            Object[] obj = underlyingComputer.Properties["ms-MCS-AdmPwdHistory"].Value as Object[];

            foreach (string str in obj)
            {
                result.Passwords.Add(str);
            }

            return result;
        }

        public BlankPasswordReport GetBlankLocalAdminPasswords()
        {
            BlankPasswordReport results = new BlankPasswordReport();
            string LdapHostname = "LDAP://" + ServerHostname;
            string searchFilter = "(&(objectClass=computer)(!(objectClass=msDS-GroupManagedServiceAccount))(!(ms-MCS-AdmPwd=*)))";
            DirectoryEntry baseContext = new DirectoryEntry(LdapHostname, BindUsername, BindPassword, AuthenticationTypes.Secure);
            DirectorySearcher computerQuery = new DirectorySearcher(baseContext, searchFilter);
            computerQuery.PropertiesToLoad.Add("name");
            computerQuery.PropertiesToLoad.Add("whenCreated");
            computerQuery.SearchScope = SearchScope.Subtree;
            SearchResultCollection searchResults = computerQuery.FindAll();

            foreach (SearchResult result in searchResults)
            {
                BlankPassword computerObject = new BlankPassword();
                computerObject.ComputerName = result.Properties["name"][0].ToString();
                string replace = LdapHostname + "/CN=" + computerObject.ComputerName + ",";
                computerObject.OrganizationalUnit = result.Path.Replace(replace, "");
                computerObject.WhenCreated = result.Properties["whenCreated"][0].ToString();
                results.ComputerNames.Add(computerObject);
            }

            return results;
        }

        public List<string> GetPasswordChangesByTime(DateTime fromDate)
        {
            List<string> results = new List<string>();
            string fileTime = fromDate.ToFileTimeUtc().ToString();

            string LdapHostname = "LDAP://" + ServerHostname;
            DirectoryEntry baseContext = new DirectoryEntry(LdapHostname, BindUsername, BindPassword, AuthenticationTypes.Secure);

            string searchFilter = "(&(objectClass=computer)(!(objectClass=msDS-GroupManagedServiceAccount))(ms-MCS-AdmPwdExpirationTime>=" + fileTime + "))";
            DirectorySearcher computerQuery = new DirectorySearcher(baseContext, searchFilter);
            computerQuery.PropertiesToLoad.Add("name");
            computerQuery.SearchScope = SearchScope.Subtree;

            SearchResultCollection searchResults = computerQuery.FindAll();

            foreach (SearchResult result in searchResults)
            {
                results.Add(result.Properties["name"][0].ToString());
            }

            return results;
        }

        public void SetLocalAdminPasswordExpiration(string computerName, DateTime newExpirationTime)
        {
            Principal searchResult = null;

            try
            {
                searchResult = SearchForComputer(computerName);
            }

            catch (Exception ex)
            {
                throw ex;
            }

            DirectoryEntry computerObject = searchResult.GetUnderlyingObject() as DirectoryEntry;
            computerObject.Properties["ms-MCS-AdmPwdExpirationTime"].Value = newExpirationTime.ToFileTime().ToString();
            computerObject.CommitChanges();
        }

        public void SetLocalAdminPasswordToExpired(string computerName)
        {
            Principal searchResult = null;

            try
            {
                searchResult = SearchForComputer(computerName);
            }

            catch (Exception ex)
            {
                throw ex;
            }

            DirectoryEntry computerObject = searchResult.GetUnderlyingObject() as DirectoryEntry;
            computerObject.Properties["ms-MCS-AdmPwdExpirationTime"].Value = 0;
            computerObject.CommitChanges();
        }
    }
}
