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

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
                               claims: claims,
                               //expires: DateTime.UtcNow.AddDays(1),
                               signingCredentials: cred);
        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return jwt;
        //return "jwt";
    }

    // do not modify the values below
    static void Main()
    {
        Console.WriteLine(
          GenerateJwtWithFixedClaims(
            "your-secret-key-1234 for generating jwt token and this key is supposed to be greater than 512 bits",
            "your-issuer",
            "your-audience",
            "sub-value-1",
            "jti-value-1",
            1626300000
          )
        );
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
*/