const express = require('express');
const fs = require('fs');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto'); // Para generar IDs internos seguros

const app = express();

// --- Configuración ---
const PORT = 4000; // O el puerto que prefieras (e.g., 3000)
app.set('trust proxy', true);

// --- Constantes ---
const USERS_FILE_PATH = path.join(__dirname, 'users.json');
const SALT_ROUNDS = 10;

// --- Almacenamiento en Memoria ---
let registeredUsers = []; // Usuarios registrados {username, passwordHash}
// Mapa principal de jugadores activos: Clave = username, Valor = objeto jugador
const players = new Map(); // Map<username, { username, internalId, ip, x, y }>
// Mapa secundario para buscar username por ID interno: Clave = internalId, Valor = username
const internalIdToUsername = new Map(); // Map<internalId, username>

// --- Funciones Auxiliares ---
const loadUsers = () => {
    try {
        if (fs.existsSync(USERS_FILE_PATH)) {
            const data = fs.readFileSync(USERS_FILE_PATH, 'utf8');
            if (data.trim() === '') {
                registeredUsers = [];
            } else {
                registeredUsers = JSON.parse(data);
                console.log(`Cargados ${registeredUsers.length} usuarios desde ${USERS_FILE_PATH}`);
            }
        } else {
            registeredUsers = [];
            console.log(`Archivo ${USERS_FILE_PATH} no encontrado. Iniciando sin usuarios.`);
        }
    } catch (error) {
        console.error('Error al cargar users.json:', error);
        registeredUsers = [];
        console.warn('Iniciando con lista de usuarios vacía debido a error.');
    }
};

const saveUsers = async () => {
    try {
        await fs.promises.writeFile(USERS_FILE_PATH, JSON.stringify(registeredUsers, null, 2), 'utf8');
        // console.log(`Usuarios guardados en ${USERS_FILE_PATH}`); // Log opcional
    } catch (error) {
        console.error('Error al guardar usuarios en users.json:', error);
    }
};

// Función para generar un ID interno único
const generateInternalId = () => {
    let newId;
    do {
        newId = crypto.randomBytes(16).toString('hex'); // 32 caracteres hexadecimales
    } while (internalIdToUsername.has(newId)); // Asegura unicidad
    return newId;
};

// --- Middleware ---
app.use(express.json());

// --- Carga Inicial ---
loadUsers();

// --- Endpoints ---

// Endpoint de Registro (sin cambios)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Nombre de usuario y contraseña son requeridos.' });
    }
    const existingUser = registeredUsers.find(user => user.username.toLowerCase() === username.toLowerCase());
    if (existingUser) {
        return res.status(409).json({ error: 'El nombre de usuario ya está registrado.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = { username: username, passwordHash: passwordHash };
        registeredUsers.push(newUser);
        await saveUsers();
        console.log(`Usuario '${username}' registrado.`);
        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (error) {
        console.error(`Error durante registro de '${username}':`, error);
        res.status(500).json({ error: 'Error interno del servidor durante el registro.' });
    }
});

// --- MODIFICADO: /join ahora es el Login ---
app.post('/join', async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.ip;

    if (!username || !password) {
        return res.status(400).json({ error: 'Nombre de usuario y contraseña son requeridos.' });
    }

    // 1. Buscar usuario registrado
    const userAccount = registeredUsers.find(user => user.username.toLowerCase() === username.toLowerCase());

    if (!userAccount) {
        console.log(`Intento de login fallido (Usuario no encontrado): ${username}`);
        return res.status(401).json({ error: 'Credenciales inválidas.' }); // 401 Unauthorized
    }

    try {
        // 2. Verificar contraseña
        const passwordMatch = await bcrypt.compare(password, userAccount.passwordHash);
        if (!passwordMatch) {
            console.log(`Intento de login fallido (Contraseña incorrecta): ${username}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' }); // 401 Unauthorized
        }

        // 3. Usuario autenticado - Gestionar sesión del jugador
        const newInternalId = generateInternalId();
        let player;

        if (players.has(userAccount.username)) {
            // El jugador ya estaba en el juego (quizás se reconecta)
            player = players.get(userAccount.username);
            console.log(`Jugador '${username}' reconectándose.`);

            // Invalidar ID interno anterior si existía
            if (player.internalId && internalIdToUsername.has(player.internalId)) {
                internalIdToUsername.delete(player.internalId);
                console.log(`ID interno anterior ${player.internalId} invalidado para ${username}.`);
            }

            // Actualizar IP e ID interno
            player.ip = clientIp;
            player.internalId = newInternalId;
            // Mantenemos su posición x, y existente
        } else {
            // Nuevo jugador uniéndose al juego tras login exitoso
            console.log(`Jugador '${username}' uniéndose al juego por primera vez (o tras reinicio del servidor).`);
            player = {
                username: userAccount.username, // ID Público
                internalId: newInternalId,      // ID Interno de sesión
                ip: clientIp,
                x: 0,                           // Posición inicial
                y: 0
            };
            players.set(userAccount.username, player); // Añadir al mapa principal
        }

        // Añadir/Actualizar mapeo del nuevo ID interno al username
        internalIdToUsername.set(newInternalId, userAccount.username);

        console.log(`Login exitoso para '${username}' desde ${clientIp}. ID interno asignado: ${newInternalId}`);

        // 4. Devolver SOLO el ID interno al cliente
        res.status(200).json({ internalId: newInternalId });

    } catch (error) {
        console.error(`Error durante el proceso de join/login para '${username}':`, error);
        res.status(500).json({ error: 'Error interno del servidor durante el login.' });
    }
});

// --- MODIFICADO: /action ahora usa internalId ---
app.post('/action', (req, res) => {
    const { internalId, action } = req.body; // Espera { "internalId": "...", "action": "..." }

    if (!internalId || !action) {
        return res.status(400).json({ error: 'internalId y action son requeridos.' });
    }

    // Buscar el username asociado al ID interno
    const username = internalIdToUsername.get(internalId);
    if (!username) {
        // ID interno inválido o expirado
        return res.status(401).json({ error: 'ID interno inválido o sesión expirada. Vuelve a unirte (/join).' });
    }

    // Obtener el objeto jugador
    const player = players.get(username);
    if (!player) {
        // Caso raro: Mapeo existe pero jugador no está en mapa principal (debería limpiarse mejor quizás)
        console.error(`Error de consistencia: internalId ${internalId} mapea a ${username}, pero no se encuentra en 'players'.`);
        internalIdToUsername.delete(internalId); // Limpiar mapeo inconsistente
        return res.status(401).json({ error: 'Error de sesión. Vuelve a unirte (/join).' });
    }

    // Verificar que el ID interno en el objeto jugador coincida (seguridad adicional)
    if (player.internalId !== internalId) {
         console.warn(`Discrepancia de internalId para ${username}. Recibido: ${internalId}, Esperado: ${player.internalId}. Rechazando acción.`);
         return res.status(401).json({ error: 'Conflicto de sesión. Vuelve a unirte (/join).'});
    }

    // Procesar la acción
    let positionChanged = true;
    switch (action.toLowerCase()) {
        case 'u': player.y -= 1; break;
        case 'd': player.y += 1; break;
        case 'l': player.x -= 1; break;
        case 'r': player.x += 1; break;
        default:
            positionChanged = false;
            return res.status(400).json({ error: `Código de acción inválido: ${action}. Usa 'u', 'd', 'l', 'r'.` });
    }

    if (positionChanged) {
        // console.log(`Jugador '${username}' (ID: ${internalId}) movido a X=${player.x}, Y=${player.y} (Acción: ${action})`); // Log opcional
        // Devolver la nueva posición
        res.status(200).json({ x: player.x, y: player.y });
    }
});
// --- MODIFICADO: /game-state usa username como ID público ---
app.get('/state', (req, res) => {
    const allPlayersData = Array.from(players.values());

    // Mapear a la estructura deseada: { username (ID público), x, y }
    const renderData = allPlayersData.map(player => ({
        username: player.username, // ID Público
        x: player.x,
        y: player.y
    }));

    res.status(200).json(renderData);
    // console.log(`Enviando estado del juego para renderizado (${renderData.length} jugadores)`); // Log opcional
});


// --- Iniciar Servidor ---
app.listen(PORT, () => {
    console.log(`Servidor del juego escuchando en http://localhost:${PORT}`);
    if (PORT <= 1024) {
        console.warn(`--- ADVERTENCIA --- Puerto ${PORT} puede requerir permisos elevados.`);
    }
});

// --- prueba de entorno ---
app.get('/game', (req, res) => {
    // Envía el archivo HTML como respuesta
    res.sendFile(path.join(__dirname, 'public', 'client.html'));
  });

  // --- prueba de entorno ---
app.get('/game-login', (req, res) => {
    // Envía el archivo HTML como respuesta
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  });