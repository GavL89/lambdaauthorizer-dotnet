using Amazon.Lambda.Core;
using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Amazon.Lambda.APIGatewayEvents;

using System.Linq;
using System.Security.Claims;
using System.Collections.Generic;
using AuthenticationService.Models;
using AuthenticationService.Managers;

namespace Authorizer
{
    public class CheckToken
    {
        public APIGatewayCustomAuthorizerResponse FunctionHandler(JObject input)
        {
            LambdaLogger.Log(input.ToString());
            IAuthService authService = new JWTService(Environment.GetEnvironmentVariable("HmacSignature"));

            string token = input.SelectToken("authorizationToken").ToString();
            APIGatewayCustomAuthorizerResponse policyResponse;

            if (!authService.IsTokenValid(token)) {
                policyResponse = GatewayPolicy(false);
                // throw new UnauthorizedAccessException();
            }  else
            {
                List<Claim> claims = authService.GetTokenClaims(token).ToList();
                string userEmail = claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Email)).Value;
                LambdaLogger.Log(userEmail);
                policyResponse = GatewayPolicy(true, userEmail);
            }
            
            return policyResponse;
        }

        public APIGatewayCustomAuthorizerResponse GatewayPolicy(Boolean allowed, string userEmail = "") {
            string effect = "Deny";
            if (allowed == true) {
                effect = "Allow";
            }

            APIGatewayCustomAuthorizerResponse response = new APIGatewayCustomAuthorizerResponse() {
                PrincipalID = userEmail,
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy {
                    Version = "2012-10-17",
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>() {
                        new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement {
                            Action = new HashSet<string>() {"execute-api:Invoke"},
                            Effect = effect,
                            Resource = new HashSet<string>() { Environment.GetEnvironmentVariable("ApiGatewayArn") }
                        }
                    }
                }
            };

            return response;
        }
    }
}