const { Passport } = require("passport");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const Usuario = require("./usuarios-modelo");
const { InvalidArgumentError } = require("../erros");

function verificaUsuario(usuario) {
  if (!usuario) {
    throw new InvalidArgumentError("Não existe usuário com esse email");
  }
}

async function verificaSenha(senha, senhaHash) {
  const senhaValida = await bcrypt.compare(senha, senhaHash);

  if (!senhaValida) {
    throw new InvalidArgumentError("Email ou senha inválidos");
  }
}

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "senha",
      session: false,
    },
    async (email, senha, done) => {
      try {
        const usuario = await Usuario.buscaPorEmail(email);
        console.log(usuario);
        verificaUsuario(usuario);
        await verificaSenha(senha, usuario.senhaHash);

        done(null, usuario);
      } catch (erro) {
        done(erro);
      }
    }
  )
);
