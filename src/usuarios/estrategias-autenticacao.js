const { Passport } = require("passport");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const BearerStrategy = require("passport-http-bearer").Strategy;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const blacklist = require("../../redis/manipula-blacklist");
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

async function verificaTokenNaBlackList(token) {
  const tokenNaBlackList = await blacklist.contemToken(token);
  if (tokenNaBlackList) {
    throw new jwt.JsonWebTokenError("Token inválido por logout");
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

passport.use(
  new BearerStrategy(async (token, done) => {
    try {
      await verificaTokenNaBlackList(token);
      const payload = jwt.verify(token, process.env.CHAVE_JWT);
      const usuario = await Usuario.buscaPorId(payload.id);
      done(null, usuario, { token: token });
    } catch (erro) {
      done(erro);
    }
  })
);
