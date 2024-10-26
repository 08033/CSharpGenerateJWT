namespace ConsoleApp1;

// class Program
// {
//     static void Main(string[] args)
//     {
//         Console.WriteLine("Hello, XD!");
//     }
// }

//Ch1: C# Generate JWT
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using Microsoft.IdentityModel.Tokens;

class MainClass
{

  public static string GenerateJwtWithFixedClaims(string secret, string issuer, string audience, string sub, string jti, long iat)
  {
    //Setting claims:
    List<Claim> claims = new List<Claim>();
    var claim1 = new Claim("sub", sub);
    var claim2 = new Claim("jti", jti);
    var claim3 = new Claim("iat", iat.ToString());
    var claim4 = new Claim(JwtRegisteredClaimNames.Iss, issuer);
    claims.Add(claim1);
    claims.Add(claim2);
    claims.Add(claim3);
    claims.Add(claim4);

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

    var token = new JwtSecurityToken(
                           claims: claims,
                           //expires: DateTime.UtcNow.AddDays(1),
                           expires: DateTime.UtcNow.AddSeconds(2),
                           signingCredentials: cred);
    var jwt = new JwtSecurityTokenHandler().WriteToken(token);
    return jwt;    
  }


  private static bool ValidateToken(string authToken, string key)
  {
    try
    {
      var tokenHandler = new JwtSecurityTokenHandler();
      var validationParameters = GetValidationParameters(key);

      SecurityToken validatedToken;
      IPrincipal principal = tokenHandler.ValidateToken(authToken, validationParameters, out validatedToken);
      return true;
    }
    catch (Exception ex)
    {
      string dt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.ms");      
      Console.WriteLine($"{dt}: Token Invalid ERROR: {ex.Message}");      
      return false;
    }
  }

  private static TokenValidationParameters GetValidationParameters(string key)
  {
    return new TokenValidationParameters()
    {
      ValidateLifetime = true,    // For expiry validation
      ClockSkew = TimeSpan.Zero,
      ValidateAudience = false,   // Because there is no audiance in the generated token
      ValidateIssuer = true,      // For issuer validation
      ValidIssuer = "your-issuer",
      ValidAudience = "Sample",      
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)) // The same key as the one that generate the token                      
    };
  }
  
  static void Main()
  {    
    string key = "your-secret-key-1234 for generating jwt token and this key is supposed to be greater than 512 bits";
    string stringToken = GenerateJwtWithFixedClaims(
        key,
        "your-issuer",
        "your-audience",
        "sub-value-1",
        "jti-value-1",
        1626300000
      );
      Console.WriteLine("JWT with Fixed Claims:");
      Console.WriteLine(stringToken);

    //key = "Changes in Key";               //To check for invalid token key;
    //System.Threading.Thread.Sleep(5000);  //To check expiry
    bool isValid = ValidateToken(stringToken, key);
    Console.WriteLine($"Token is valid: {isValid}");
  }

}

//-----References:
/*
1- https://learn.microsoft.com/en-us/dotnet/core/tutorials/with-visual-studio-code?pivots=dotnet-8-0
2- https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens/ (add package)
3- https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/ (add package)  
4- https://www.ais.com/how-to-generate-a-jwt-token-using-net-6/
5- https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytoken?view=msal-web-dotnet-latest
6- https://stackoverflow.com/questions/47279947/idx10603-the-algorithm-hs256-requires-the-securitykey-keysize-to-be-greater
7- https://stackoverflow.com/questions/50204844/how-to-validate-a-jwt-token
*/
