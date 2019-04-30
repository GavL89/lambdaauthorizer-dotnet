using Amazon.Lambda.Core;
using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using System.Linq;
using System.Security.Claims;
using System.Collections.Generic;
using AuthenticationService.Models;
using AuthenticationService.Managers;

namespace Authorizer
{
    public class Authenticate
    {
        public JObject FunctionHandler(JObject input)
        {
            string status;
            string data;
            
            try {
                // You should reference any logic or functions which authenticate your user here and then pass any data as claims to GetJWTContainerModel
                string UserName = "user@domain.com";                                    

                IAuthContainerModel model = JWTService.GetJWTContainerModel(UserName);
                IAuthService authService = new JWTService(model.SecretKey);
                string jwt = authService.GenerateToken(model);

                status = "SUCCESS";
                data = jwt;
            } catch (Exception e) {
                status = "ERROR"; // Should really handle errors better than this
                data = e.Message;
                LambdaLogger.Log(e.Message); 
            }    

            JObject result = new JObject();
            result.Add("status", status);
            result.Add("data", data);

            return result;
        }
    }
}