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
import Control.Monad.IO.Class
  
data LDAPAuthResult = Ok [LDAPEntry]
                    | NoSuchUser
                    | WrongPassword
                    | InitialBindFail

instance Show LDAPAuthResult where
  show (Ok _            )         = "Login successful"
  show NoSuchUser                 = "Wrong username"
  show WrongPassword              = "Wrong password"
  show InitialBindFail            = "The initial bind attempt to the ldap" ++
                                    "server failed"
   
loginLDAP :: Text -> -- user's identifier
             String -> -- user's DN
             String -> -- user's password
             String -> -- LDAPHost
             LDAPInt -> -- LDAP port
             String -> -- DN for initial bind
             String -> -- Password for initial bind
             Maybe String -> --  Base DN for user search, if any
             LDAPScope -> -- Scope of User search
             IO LDAPAuthResult
loginLDAP user userDN pass ldapHost ldapPort' initDN initPassword searchDN ldapScope =
  do
   ldapOBJ <- ldapInit ldapHost ldapPort'
   initBindResult <- try (ldapSimpleBind ldapOBJ initDN initPassword) 
                                                 :: IO (Either LDAPException ())
   case initBindResult of
     Right _ -> do -- Successful initial bind
       entry <- ldapSearch ldapOBJ
                           searchDN
                           ldapScope
                           (Just ("sAMAccountName=" ++  (unpack user)))
                           LDAPAllUserAttrs
                           False
-- FIXME y u no make new function for nested case statement?       
       case entry of
         [LDAPEntry _ _] -> do
                             ldapOBJ' <- ldapInit ldapHost ldapPort'  
                             userBindResult <- try (ldapSimpleBind ldapOBJ' userDN pass) :: IO (Either LDAPException ())
                             case userBindResult of
                               Right _ -> return $ Ok entry -- Successful user bind
                               Left _ -> return WrongPassword
         _               -> return NoSuchUser
     Left _ -> return InitialBindFail    
