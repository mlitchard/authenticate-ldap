{-# LANGUAGE OverloadedStrings #-}
-- | Module for using LDAP as an authentication service
-- 
-- This code was written for yesod-auth-ldap, but maybe it can be used in any 
-- given Haskell web framwork?
-- For now, the only usage examples will be Yesod specific. So you can find
-- them in the yesod-auth-ldap repo 

module Web.Authenticate.LDAP
  ( loginLDAP
  , LDAPAuthResult (..)
  ) where

import Data.Text (Text,unpack)
import LDAP
import Control.Exception

  
data LDAPAuthResult = Ok [LDAPEntry]
                    | NoSuchUser
                    | WrongPassword

instance Show LDAPAuthResult where
  show (Ok _            )         = "Login successful"
  show NoSuchUser                 = "Wrong username"
  show WrongPassword              = "Wrong password"
   
loginLDAP :: Text -> -- user's identifier
             String -> -- user's password
             String -> -- LDAPHost
             LDAPInt -> -- LDAP port
             String -> -- DN for initial bind
             String -> -- Password for initial bind
             Maybe String -> --  Base DN for user search, if any
             LDAPScope -> -- Scope of User search
             IO LDAPAuthResult
loginLDAP user pass ldapHost ldapPort' initDN initPassword searchDN ldapScope =
  do
   ldapOBJ <- ldapInit ldapHost ldapPort'
   initBindResult <- try (ldapSimpleBind ldapOBJ initDN initPassword) 
                                                 :: IO (Either LDAPException ())
   case initBindResult of
     Left _ -> do -- Successful initial bind
       ldapOBJ' <- ldapInit ldapHost ldapPort'
       userBindResult <- try (ldapSimpleBind ldapOBJ' (unpack user) pass) 
                                                 :: IO (Either LDAPException ())
       case userBindResult of
         Left _ -> do -- Successful user bind
           entry <- ldapSearch ldapOBJ  
                               searchDN 
                               ldapScope
                               (Just ("sAMAccountName=" ++ (unpack user)))
                               LDAPAllUserAttrs
                               False
           return $ Ok entry
         Right _ -> return WrongPassword
     Right _ -> return NoSuchUser    
