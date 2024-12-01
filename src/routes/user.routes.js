import { Router } from "express";
import { 
    login,
    logout,
    register, 
    refreshAccessToken,
    getSosContacts,
    changePassword,
    updateSosContacts
} from "../controllers/user.controller.js";
import verifyJWT from "../middlewares/auth.middleware.js";

const router = Router()

router.route("/register").post(register)
router.route("/login").post(login)
router.route("/logout").post(verifyJWT, logout)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/change-password").post(verifyJWT, changePassword)
router.route('/sos').get(verifyJWT, getSosContacts);
router.route('/updatecontacts').post(verifyJWT, updateSosContacts)

export default router;