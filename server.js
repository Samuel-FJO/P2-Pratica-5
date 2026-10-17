const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const verifyToken = require('./authMiddleware');
require('dotenv').config();

const app = express();
app.use(express.json());

// ==========================================
// ROTAS PÚBLICAS
// ==========================================

// 1. Rota de Login (Gera o Token JWT)
app.post('/login', async (req, res) => {
  const { login_email, password } = req.body;

  try {
    const result = await db.query('SELECT * FROM sys_user WHERE login_email = $1', [login_email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Usuário ou senha incorretos.' });
    }

    const user = result.rows[0];

    // Para fins pedagógicos/simplificados de acordo com a carga inicial:
    if (password !== user.password) {
      return res.status(400).json({ message: 'Usuário ou senha incorretos.' });
    }

    // Gerar Token JWT com id e tipo de usuário
    const token = jwt.sign(
      { id: user.id, user_type: user.user_type, login_email: user.login_email },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({ message: 'Autenticado com sucesso!', token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Consulta Simples: Passageiros
app.get('/passengers', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM passenger LIMIT 100');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Consulta Simples: Aeronaves
app.get('/aircrafts', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM aircraft');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Consulta Simples: Voos
app.get('/flights', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM flight LIMIT 100');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. ROTA DE JUNÇÃO (JOIN exata solicitada na atividade - Importante para teste de carga)
app.get('/boarding-passes/full', async (req, res) => {
  const queryText = `
    SELECT
        bp.boarding_pass_id AS boarding_pass_id,
        bp.seat_number AS seat_number,
        bp.issue_time AS issue_time,
        p.first_name AS passenger_first_name,
        p.last_name AS passenger_last_name,
        p.birth_date AS passenger_birth_date,
        p.passport_number AS passenger_passport_number,
        f.flight_number AS flight_number,
        f.departure_airport AS departure_airport,
        f.arrival_airport AS arrival_airport,
        f.departure_time AS departure_time,
        f.arrival_time AS arrival_time,
        a.model AS aircraft_model,
        a.manufacturer AS aircraft_manufacturer,
        a.capacity AS aircraft_capacity
    FROM
        boarding_pass bp
    JOIN
        passenger p ON bp.passenger_id = p.passenger_id
    JOIN
        flight f ON bp.flight_id = f.flight_id
    JOIN
        aircraft a ON f.aircraft_id = a.aircraft_id
    ORDER BY
        bp.boarding_pass_id
    LIMIT 100;
  `;
  try {
    const result = await db.query(queryText);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ROTAS PRIVADAS (CRUD sys_user com JWT)
// ==========================================

// Listar todos os usuários (Protegido)
app.get('/users', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT id, name, login_email, user_type FROM sys_user');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Criar novo usuário (Apenas "admin")
app.post('/users', verifyToken, async (req, res) => {
  if (req.user.user_type !== 'admin') {
    return res.status(403).json({ message: 'Acesso negado. Apenas administradores podem cadastrar novos usuários.' });
  }

  const { name, login_email, password, user_type } = req.body;
  try {
    const result = await db.query(
      'INSERT INTO sys_user (name, login_email, password, user_type) VALUES ($1, $2, $3, $4) RETURNING id, name, login_email, user_type',
      [name, login_email, password, user_type]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar usuário (Admin altera qualquer um; Regular altera apenas o próprio)
app.put('/users/:id', verifyToken, async (req, res) => {
  const targetId = parseInt(req.params.id);

  if (req.user.user_type !== 'admin' && req.user.id !== targetId) {
    return res.status(403).json({ message: 'Acesso negado. Você só pode atualizar seus próprios dados.' });
  }

  const { name, password } = req.body;
  try {
    const result = await db.query(
      'UPDATE sys_user SET name = $1, password = $2 WHERE id = $3 RETURNING id, name, login_email, user_type',
      [name, password, targetId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deletar usuário (Apenas "admin")
app.delete('/users/:id', verifyToken, async (req, res) => {
  if (req.user.user_type !== 'admin') {
    return res.status(403).json({ message: 'Acesso negado. Apenas administradores podem remover usuários.' });
  }

  const targetId = parseInt(req.params.id);
  try {
    await db.query('DELETE FROM sys_user WHERE id = $1', [targetId]);
    res.json({ message: 'Usuário removido com sucesso.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});