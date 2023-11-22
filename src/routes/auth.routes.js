import { Router } from "express";
import { login,register,logout,obtener,generarContrasena, obtenerContrasenasUsuario } from "../controllers/auth.controller.js";
import {authRequired} from "../middlewares/validateToken.js";
const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);

router.get( '/obtener', obtener);
router.post('/generar-contrasena',authRequired, generarContrasena);
router.get('/ obtenerContrasenasUsuario',authRequired, obtenerContrasenasUsuario)
export default router; 