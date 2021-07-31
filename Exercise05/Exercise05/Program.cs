using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;


namespace Exercise05
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create an XmlDocument object.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML file into the XmlDocument object.
            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load("xmlFile.xml");

                string xmlcontents = xmlDoc.InnerXml;

                Console.WriteLine(xmlcontents);


            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
            }

            // Create a new RSA key.  This key will encrypt a symmetric key which will then be imbedded in the XML document.
            RSA rsaKey = RSA.Create();

            try
            {
                // Encrypt the "creditcard" element.
                Encrypt(xmlDoc, "creditcard", rsaKey, "rsaKey");

                HashPassword(xmlDoc, "password");

            }
            catch (Exception ex)
            {

                throw ex;
            }
        }


        public static void Encrypt(XmlDocument Doc, string ElementToEncrypt, RSA Alg, string KeyName)
        {
            try
            {
                if (Doc == null)
                {
                    throw new ArgumentException("Doccument missing!");
                }

                if(ElementToEncrypt == null)
                {
                    throw new ArgumentException("Element to Encrypt missing!");
                }

                if(Alg == null)
                {
                    throw new ArgumentException("Element to Encrypt missing!");
                }

                XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;

         

                if (elementToEncrypt == null)
                {
                    throw new XmlException("The specified element was not found");
                }

                // Create a 256 bit Aes key.
                Aes sessionKey = Aes.Create();
                sessionKey.KeySize = 256;

                EncryptedXml eXml = new EncryptedXml();

                byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);

                // Construct an EncryptedData object and populate it with the desired encryption information.

                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;

                // Create an EncryptionMethod element so that the receiver knows which algorithm to use for decryption.

                edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

                // Encrypt the session key and add it to an EncryptedKey element.
                EncryptedKey ekey = new EncryptedKey();

                byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, Alg, false);

                ekey.CipherData = new CipherData(encryptedKey);

                ekey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);

                // Set the KeyInfo element to specify the name of the RSA key.

                // Create a new KeyInfo element.
                edElement.KeyInfo = new KeyInfo();

                // Create a new KeyInfoName element.
                KeyInfoName kin = new KeyInfoName();

                // Specify a name for the key.
                kin.Value = KeyName;

                // Add the KeyInfoName element to the EncryptedKey object.
                ekey.KeyInfo.AddClause(kin);

                // Add the encrypted key to the EncryptedData object.

                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ekey));

                // Add the encrypted element data to the EncryptedData object.
                edElement.CipherData.CipherValue = encryptedElement;

                
                // Replace the element from the original XmlDocument object with the EncryptedData element.
             

                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);

            }
            catch (Exception ex)
            {

                throw ex;
            }


        }

        public static string  HashPassword(XmlDocument Doc, string ElementToHash)
        {

            if (Doc == null)
            {
                throw new ArgumentException("Doccument missing!");
            }

            XmlElement elementToHash = Doc.GetElementsByTagName(ElementToHash)[0] as XmlElement;

            var password = elementToHash.InnerText;

            string pwd = password;
            string salt = GenerateSalt(70);
            string pwdHashed = HashPassword(pwd, salt, 10101, 70);

            return pwdHashed;

        }
        public static string GenerateSalt(int nSalt)
        {
            var saltBytes = new byte[nSalt];

            using (var provider = new RNGCryptoServiceProvider())
            {
                provider.GetNonZeroBytes(saltBytes);
            }

            return Convert.ToBase64String(saltBytes);
        }

        public static string HashPassword(string password, string salt, int nIterations, int nHash)
        {
            var saltBytes = Convert.FromBase64String(salt);

            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, saltBytes, nIterations))
            {
                return Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(nHash));
            }
        }


    }



}
