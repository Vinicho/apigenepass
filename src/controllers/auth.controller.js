import bcrypt from 'bcryptjs';
import { query } from '../db.js';
import {createAccesToken} from '../libs/jwt.js';
export const register = async (req, res) => {
    const { usuario, correo, contraseña } = req.body;

    try {
            const existingUser = await query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);

        if (existingUser.length > 0) {
        return res.status(400).json({ error: 'El usuario ya existe. Por favor, elige otro nombre de usuario.' });
        }

        const contraseñaHasheada = await bcrypt.hash(contraseña, 10);
        await query('INSERT INTO usuarios (usuario, correo, contraseña) VALUES (?, ?, ?)', [usuario, correo, contraseñaHasheada]);

        const token = createAccesToken({ usuario, correo });
        res.cookie('token', token);
        return res.status(201).json({ mensaje: 'Cuenta creada exitosamente.' });
    }catch (error) {
        console.error('Error en el registro:', error);
        return res.status(500).json({ error: 'Error en el registro.' });
    }
};

export const login = async (req, res) => {
    const { usuario, contraseña } = req.body;

    try {
        const usuarioEncontrado = await query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);

        if (usuarioEncontrado.length === 0) {
        return res.status(401).json({ error: 'Usuario no encontrado. Por favor, regístrate.' });
        }

        const coincidenciaContraseña = await bcrypt.compare(contraseña, usuarioEncontrado[0].contraseña);
        if (coincidenciaContraseña) {
        const token = createAccesToken({ usuario });
        res.cookie('token', token);
        return res.status(200).json({ mensaje: `Inicio de sesión exitoso. ¡Bienvenido, ${usuario}!` });
        } else {
        return res.status(401).json({ error: 'Contraseña incorrecta. Por favor, inténtalo de nuevo.' });
        }
    } catch (error) {
        console.error('Error en el inicio de sesión:', error);
        return res.status(500).json({ error: 'Error en el inicio de sesión.' });
    }
};

export const logout = (req, res) => {
    res.cookie('token', '', {
        expires: new Date(0),
    });
    return res.sendStatus(200);
};

export const obtener = async (req, res) => {
    const userlog = req.user;
console.log(userlog)
    try {
        const usuarioEncontrado = await query('SELECT * FROM usuarios');       
        res.json(usuarioEncontrado);
    } catch (error) {
        console.error('Error al obtener usuario:', error);
        res.status(500).json({ error: 'Error al obtener usuario.' });
    }
};




export const generarContrasena = async (req, res) => {
    const { longitud, mayusculas, minusculas, numeros, especiales, sitio } = req.body;
    const usuarioLogueado = req.user; 
    
    let caracteresSeleccionados = '';
    if (mayusculas) {
        caracteresSeleccionados += 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ';
    }
    if (minusculas) {
        caracteresSeleccionados += 'abcdefghijklmnñopqrstuvwxyz';
    }
    if (numeros) {
        caracteresSeleccionados += '0123456789';
    }
    if (especiales) {
        caracteresSeleccionados += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    }
    if (!caracteresSeleccionados) {
        return res.status(400).json({ error: 'Debes seleccionar al menos un tipo de caracteres.' });
    }

    const contraseñaGenerada = generarContrasenaAleatoria(longitud, caracteresSeleccionados);
    
    try {

        await guardarContrasenaGenerada(usuarioLogueado, contraseñaGenerada, sitio); 
        res.status(200).json({ contraseña: contraseñaGenerada });
    } catch (error) {
        console.error('Error al guardar la contraseña generada:', error);
        res.status(500).json({ error: 'Error al guardar la contraseña generada.' });
    }
    };

async function guardarContrasenaGenerada(usuario, contraseñaGenerada, sitio) {
    try {
        await query('INSERT INTO passwords (usuario, password, sitio) VALUES (?, ?, ?)', [usuario, contraseñaGenerada, sitio]);
    } catch (error) {
        throw error;
    }
}  

export const obtenerContrasenasUsuario = async (req, res) => {
    const usuarioLogueado = req.user;

    try {
        const contrasenasUsuario = await query('SELECT * FROM passwords WHERE usuario = ?', [usuarioLogueado]);

        if (contrasenasUsuario.length === 0) {
            return res.status(404).json({ mensaje: 'No se encontraron contraseñas para este usuario.' });
        }
        return res.status(200).json({ contrasenas: contrasenasUsuario });
    } catch (error) {
        console.error('Error al obtener contraseñas del usuario:', error);
        return res.status(500).json({ error: 'Error al obtener contraseñas del usuario.' });
    }
};
