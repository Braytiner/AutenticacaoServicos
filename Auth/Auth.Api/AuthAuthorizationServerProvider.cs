using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;
using System.Security.Claims;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;

namespace Auth.Api
{
    public class AuthAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //Verifica se o token existe no cache criado pelo o OAuth e se o mesmo é válido 
            //Se o token não for válido irá cair no segundo método
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Acces-Control-Allow-Origin", new[] { "*" });

            try
            {
                var usuario = context.UserName;
                var senha = context.Password;

                //Aqui deveria ser feita a validação verificando o nome do usuário e senha no banco 
                //de dados
                if ((usuario != "braytiner") || (senha != "1234"))
                {
                    context.SetError("invalid_grant", "Usuário ou senha inválidos!");
                    return;
                }

                var identidade = new ClaimsIdentity(context.Options.AuthenticationType);
                identidade.AddClaim(new Claim(ClaimTypes.Name, usuario));

                var roles = new List<string>();
                //roles.Add("Admin");
                roles.Add("User");

                foreach (var role in roles)
                    identidade.AddClaim(new Claim(ClaimTypes.Role, role));

                //Setando usuário principal desta thread
                GenericPrincipal principal = new GenericPrincipal(identidade, roles.ToArray());
                Thread.CurrentPrincipal = principal;

                context.Validated(identidade);
            }
            catch (System.Exception)
            {

                context.SetError("invalid_grant", "Falha ao autenticar");
            }
        }
    }
}