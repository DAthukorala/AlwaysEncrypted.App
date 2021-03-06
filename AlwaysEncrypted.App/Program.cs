﻿using Microsoft.Web.Services2.Security.X509;
using System;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certificate = System.Security.Cryptography.X509Certificates;

namespace AlwaysEncrypted.App
{
    class Program
    {
        static void Main(string[] args)
        {
            SetupAlwaysEncryptedColumn();

            Console.ReadLine();
        }

        private static string GetThumbprinOfCertByName(string subjectName)
        {
            var certificate = GetCertificatBySubjectName(subjectName);
            var thumbprint = certificate?.Thumbprint;
            return thumbprint;
        }

        private static void SetupAlwaysEncryptedColumn()
        {
            //get the tumbprint on button click
            var thumbprint = GetThumbprinOfCertByName("AlwaysEncryptedCert");
            //create the column master key using the thumb print (SQL: CREATE COLUMN MASTER KEY )
            //reate the column encryption key using the column master key
            var columnEncryptionKey = GetEncryptionKey(thumbprint);
            //create the column encryption key using this value (SQL: CREATE COLUMN ENCRYPTION KEY, use RSA_OAEP)
            //create a column with always encryption on ()SQL: ALTER TABLE USERS)
        }        

        private static Certificate.X509Certificate2 GetCertificatBySubjectName(string subject)
        {
            //open local certification store, that stores the certificates used to generate the machine key
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var certificates = store.Certificates;
            //find the certificate by name
            var matched = certificates.Find(X509FindType.FindBySubjectName, subject, false);
            var certificate = matched.Count > 0 ? matched[0] : null;
            return certificate;
        }

        private static string GetEncryptionKey(string thumbprint)
        {
            var randomBytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            //get the built in sql certificate store provider
            var provider = new SqlColumnEncryptionCertificateStoreProvider();
            //get the column master key
            var encryptedKey = provider.EncryptColumnEncryptionKey($"LocalMachine/My/{thumbprint}", "RSA_OAEP", randomBytes);
            //create encrypted data thats used to create the column encryption key
            var encryptedKeySerialized = "0x" + BitConverter.ToString(encryptedKey).Replace("-", "");
            return encryptedKeySerialized;
        }
    }
}
