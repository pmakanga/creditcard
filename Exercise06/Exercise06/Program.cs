using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.Xml;

namespace Exercise06
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
            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
            }

            // Create a new RSA key.  This key will encrypt a symmetric key which will then be imbedded in the XML document.
            RSA rsaKey = RSA.Create();

            try
            {

                // Decrypt the "creditcard" element.
                Decrypt(xmlDoc, rsaKey, "rsaKey");
            }
            catch (Exception ex)
            {

                throw ex;
            }
        }

        public static void Decrypt(XmlDocument Doc, RSA Alg, string KeyName)
        {
            // Check the arguments.
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (Alg == null)
                throw new ArgumentNullException("Alg");
            if (KeyName == null)
                throw new ArgumentNullException("KeyName");

            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml(Doc);

            // Add a key-name mapping.

            exml.AddKeyNameMapping(KeyName, Alg);

            // Decrypt the element.
            exml.DecryptDocument();
        }
    }
}
