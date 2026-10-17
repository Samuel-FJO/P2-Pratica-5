const jwt = require('jsonwebtoken');
require('dotenv').config();

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // Salva os dados do usuário (id, user_type) na requisição
    next();
  } catch (err) {
    res.status(403).json({ message: 'Token inválido ou expirado.' });
  }
}

module.exports = verifyToken;