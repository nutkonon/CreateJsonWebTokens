using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace WebApplication1
{
    public partial class WebForm1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            string jwt = string.Empty;
            var fileStream = new FileStream(@"Private Key Path", FileMode.Open, FileAccess.Read);
            AsymmetricCipherKeyPair keypair;
            using (StreamReader streamReader = new StreamReader(fileStream, Encoding.UTF8))
            {
                PemReader pr = new PemReader(streamReader);
                keypair = (AsymmetricCipherKeyPair)pr.ReadObject();
            }
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keypair.Private);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                var payload = new { value = "value" };
                jwt = Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
            }
            Label1.Text = jwt;
        }
    }
}