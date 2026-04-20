// ============================================================
//  SEGURIDAD — NOTAS IMPORTANTES
//  1. Este archivo NO debe contener la API key de Firebase.
//     La config está en firebase-config.js (ignorado por Git).
//  2. Las reglas de Firestore (firestore.rules) son la capa
//     de seguridad principal en el servidor.
//  3. La contraseña abajo es solo una barrera de primera línea.
//     NO es criptografía real. Para producción crítica, usa
//     Firebase Authentication con correo/contraseña.
// ============================================================

// ── 1. CONTRASEÑA DE ACCESO ──────────────────────────────────
const HASH_CONTRASENA = "11dce0ae8ac8dc202d3d";


// ── 2. LÍMITES DE SEGURIDAD ──────────────────────────────────
const MAX_INTENTOS = 5;           // Intentos antes de bloquear
const TIEMPO_BLOQUEO_SEG = 60;    // Segundos de bloqueo
const MONTO_MAXIMO = 9_999_999;   // Monto máximo permitido ($)
const MONTO_MINIMO = 1;           // Monto mínimo permitido ($)
const TIMEOUT_SESION_MIN = 30;    // Minutos antes de cerrar sesión automáticamente

// ── 3. ESTADO INTERNO ────────────────────────────────────────
let intentosFallidos = 0;
let bloqueadoHasta = null;
let sesionActiva = false;
let timerSesion = null;
let db = null;

// ── 4. LISTA DE INTEGRANTES ──────────────────────────────────
// MANTÉN esta lista actualizada. Nunca llegue desde el cliente.
const listaIntegrantes = [
    "Cristóbal José Valdés Pezo",
    "Vicente Ignacio Cuitiño Sage",
    "Diego Soto",
    "Ana Rojas",
    "Carlos Muñoz"
];

// ── 5. UTILIDADES ─────────────────────────────────────────────

/**
 * Hash SHA-256 usando la Web Crypto API nativa del navegador.
 * No requiere ninguna librería externa.
 */
async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Sanitiza texto: elimina caracteres peligrosos y espacios extra.
 * Previene inyecciones básicas en los datos guardados.
 */
function sanitizarTexto(texto) {
    return texto.trim().replace(/[<>"'`]/g, "");
}

/**
 * Valida que un monto sea un número real dentro de los límites.
 */
function validarMonto(valor) {
    const n = parseFloat(valor);
    if (isNaN(n)) return { ok: false, msg: "El monto no es un número válido." };
    if (n < MONTO_MINIMO) return { ok: false, msg: `El monto mínimo es $${MONTO_MINIMO}.` };
    if (n > MONTO_MAXIMO) return { ok: false, msg: `El monto máximo es $${MONTO_MAXIMO.toLocaleString()}.` };
    if (!Number.isFinite(n)) return { ok: false, msg: "Monto inválido." };
    return { ok: true, valor: Math.round(n) }; // Redondeamos para evitar decimales raros
}

/**
 * Verifica que el nombre sea uno de los integrantes autorizados.
 * Previene que alguien manipule el DOM para ingresar nombres arbitrarios.
 */
function validarIntegrante(nombre) {
    return listaIntegrantes.includes(nombre);
}

// ── 6. AUTENTICACIÓN POR CONTRASEÑA ──────────────────────────

async function verificarPin() {
    // ¿Está bloqueado?
    if (bloqueadoHasta && Date.now() < bloqueadoHasta) return;

    const input = document.getElementById("pin-input");
    const valor = input.value;

    if (!valor) return;

    const hash = await sha256(valor);
    const hashParcial = hash.substring(0, 20);

    if (hashParcial === HASH_CONTRASENA) {
        // Acceso correcto
        intentosFallidos = 0;
        sesionActiva = true;
        document.getElementById("pin-screen").style.display = "none";
        document.getElementById("app-screen").classList.add("visible");
        iniciarTimerSesion();
        poblarMenusDesplegables();
        inicializarFirebase();
    } else {
        intentosFallidos++;
        input.value = "";

        if (intentosFallidos >= MAX_INTENTOS) {
            bloquearAcceso();
        } else {
            const restantes = MAX_INTENTOS - intentosFallidos;
            document.getElementById("pin-error").textContent = "Contraseña incorrecta.";
            document.getElementById("pin-attempts").textContent =
                `${restantes} intento${restantes !== 1 ? "s" : ""} restante${restantes !== 1 ? "s" : ""}.`;
        }
    }
}

function bloquearAcceso() {
    bloqueadoHasta = Date.now() + TIEMPO_BLOQUEO_SEG * 1000;
    document.getElementById("pin-screen").style.display = "none";
    const lockedScreen = document.getElementById("locked-screen");
    lockedScreen.classList.add("visible");

    let segundos = TIEMPO_BLOQUEO_SEG;
    const countdown = document.getElementById("countdown");
    countdown.textContent = segundos;

    const timer = setInterval(() => {
        segundos--;
        countdown.textContent = segundos;
        if (segundos <= 0) {
            clearInterval(timer);
            intentosFallidos = 0;
            bloqueadoHasta = null;
            lockedScreen.classList.remove("visible");
            document.getElementById("pin-screen").style.display = "block";
            document.getElementById("pin-error").textContent = "";
            document.getElementById("pin-attempts").textContent = "";
        }
    }, 1000);
}

function cerrarSesion() {
    sesionActiva = false;
    if (timerSesion) clearTimeout(timerSesion);
    document.getElementById("app-screen").classList.remove("visible");
    document.getElementById("pin-screen").style.display = "block";
    document.getElementById("pin-input").value = "";
    document.getElementById("pin-error").textContent = "";
    document.getElementById("pin-attempts").textContent = "";
    db = null;
}

/**
 * Cierra sesión automáticamente después de TIMEOUT_SESION_MIN minutos de inactividad.
 */
function iniciarTimerSesion() {
    if (timerSesion) clearTimeout(timerSesion);
    timerSesion = setTimeout(() => {
        if (sesionActiva) {
            alert("Tu sesión expiró por inactividad. Por seguridad, debes volver a ingresar.");
            cerrarSesion();
        }
    }, TIMEOUT_SESION_MIN * 60 * 1000);
}

// Reinicia el timer con cualquier interacción del usuario
function resetearTimerInactividad() {
    if (sesionActiva) iniciarTimerSesion();
}

// ── 7. FIREBASE ───────────────────────────────────────────────

function inicializarFirebase() {
    try {
        if (typeof firebaseConfig === "undefined") {
            alert("Error: No se encontró firebase-config.js");
            return;
        }
        firebase.initializeApp(firebaseConfig);
        db = firebase.firestore();
    } catch (error) {
        // Si ya estaba inicializado (ej: recarga sin cerrar sesión)
        if (error.code === "app/duplicate-app") {
            db = firebase.firestore();
            poblarMenusDesplegables();
        } else {
            console.error("Error inicializando Firebase:", error);
            alert("Error de conexión con la base de datos.");
        }
    }
}

// ── 8. INTERFAZ ───────────────────────────────────────────────

function poblarMenusDesplegables() {
    const menuComprar = document.getElementById("nombre-comprar");
    const menuPagar = document.getElementById("nombre-pagar");

    // Limpia opciones anteriores (seguridad: evita duplicados si se llama dos veces)
    menuComprar.innerHTML = '<option value="">Selecciona un nombre…</option>';
    menuPagar.innerHTML = '<option value="">Selecciona un nombre…</option>';

    listaIntegrantes.forEach(nombre => {
        const crearOpcion = () => {
            const opt = document.createElement("option");
            opt.value = nombre;
            opt.textContent = nombre; // textContent es más seguro que innerHTML
            return opt;
        };
        menuComprar.appendChild(crearOpcion());
        menuPagar.appendChild(crearOpcion());
    });
}

function mostrarSeccion(opcion, btnEl) {
    if (!sesionActiva) return;
    resetearTimerInactividad();

    document.getElementById("seccion-comprar").classList.remove("active");
    document.getElementById("seccion-pagar").classList.remove("active");

    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    if (btnEl) btnEl.classList.add("active");

    document.getElementById(`seccion-${opcion}`).classList.add("active");
}

// ── 9. BASE DE DATOS ──────────────────────────────────────────

async function consultarDeuda(nombre) {
    if (!sesionActiva || !db) return;
    resetearTimerInactividad();

    const inputDeuda = document.getElementById("monto-a-pagar");
    const badge = document.getElementById("deuda-badge");
    const badgeAmount = document.getElementById("deuda-amount");

    if (!nombre) {
        inputDeuda.value = "";
        badge.classList.remove("visible");
        return;
    }

    // Verificar que el nombre sea válido (no manipulado en el DOM)
    if (!validarIntegrante(nombre)) {
        alert("Nombre no reconocido.");
        return;
    }

    inputDeuda.placeholder = "Consultando…";

    try {
        const userRef = db.collection("usuarios").doc(nombre);
        const doc = await userRef.get();

        const deuda = doc.exists ? (doc.data().deuda || 0) : 0;
        inputDeuda.value = deuda;

        if (deuda > 0) {
            badgeAmount.textContent = `$${deuda.toLocaleString("es-CL")}`;
            badge.classList.add("visible");
        } else {
            badge.classList.remove("visible");
        }
    } catch (error) {
        console.error("Error al consultar deuda:", error);
        inputDeuda.placeholder = "Error de conexión";
        badge.classList.remove("visible");
    }
}

async function validarCompra() {
    if (!sesionActiva || !db) return;
    resetearTimerInactividad();

    const btn = document.querySelector("#seccion-comprar .btn-submit");
    const nombre = sanitizarTexto(document.getElementById("nombre-comprar").value);
    const montoStr = document.getElementById("monto-gastado").value;

    if (!nombre) {
        alert("Por favor selecciona un nombre.");
        return;
    }

    // Validación: nombre debe ser de la lista autorizada
    if (!validarIntegrante(nombre)) {
        alert("Nombre no autorizado.");
        return;
    }

    const montoValidado = validarMonto(montoStr);
    if (!montoValidado.ok) {
        alert(montoValidado.msg);
        return;
    }

    const monto = montoValidado.valor;
    const confirmacion = confirm(`¿Confirmas que ${nombre} compró por $${monto.toLocaleString("es-CL")}?`);

    if (!confirmacion) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Registrando…';

    try {
        const userRef = db.collection("usuarios").doc(nombre);
        const doc = await userRef.get();

        const deudaActual = doc.exists ? (doc.data().deuda || 0) : 0;
        const nuevaDeuda = deudaActual + monto;

        await userRef.set({ deuda: nuevaDeuda }, { merge: true });

        alert(`✅ Compra registrada. Nueva deuda de ${nombre}: $${nuevaDeuda.toLocaleString("es-CL")}`);

        document.getElementById("nombre-comprar").value = "";
        document.getElementById("monto-gastado").value = "";
    } catch (error) {
        console.error("Error al registrar compra:", error);
        alert("❌ Error al guardar en la base de datos. Intenta nuevamente.");
    } finally {
        btn.disabled = false;
        btn.textContent = "Registrar Compra";
    }
}

async function validarPago() {
    if (!sesionActiva || !db) return;
    resetearTimerInactividad();

    const btn = document.querySelector("#seccion-pagar .btn-submit");
    const nombre = sanitizarTexto(document.getElementById("nombre-pagar").value);
    const montoStr = document.getElementById("monto-pagado").value;
    const deudaActualStr = document.getElementById("monto-a-pagar").value;

    if (!nombre) {
        alert("Por favor selecciona un nombre.");
        return;
    }

    if (!validarIntegrante(nombre)) {
        alert("Nombre no autorizado.");
        return;
    }

    const montoValidado = validarMonto(montoStr);
    if (!montoValidado.ok) {
        alert(montoValidado.msg);
        return;
    }

    const monto = montoValidado.valor;
    const deudaActual = parseFloat(deudaActualStr) || 0;

    // Advertencia si el pago supera la deuda
    if (monto > deudaActual && deudaActual > 0) {
        const continuar = confirm(
            `El monto a pagar ($${monto.toLocaleString("es-CL")}) supera la deuda actual ($${deudaActual.toLocaleString("es-CL")}).\n¿Deseas continuar de todas formas?`
        );
        if (!continuar) return;
    }

    const confirmacion = confirm(`¿Confirmas que ${nombre} pagará $${monto.toLocaleString("es-CL")}?`);
    if (!confirmacion) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Procesando…';

    try {
        const userRef = db.collection("usuarios").doc(nombre);
        const doc = await userRef.get();

        const deudaEnBD = doc.exists ? (doc.data().deuda || 0) : 0;
        const nuevaDeuda = deudaEnBD - monto;

        await userRef.set({ deuda: nuevaDeuda }, { merge: true });

        alert(`✅ Pago registrado. Deuda restante de ${nombre}: $${nuevaDeuda.toLocaleString("es-CL")}`);

        document.getElementById("nombre-pagar").value = "";
        document.getElementById("monto-pagado").value = "";
        consultarDeuda("");
    } catch (error) {
        console.error("Error al registrar pago:", error);
        alert("❌ Error al procesar el pago. Intenta nuevamente.");
    } finally {
        btn.disabled = false;
        btn.textContent = "Registrar Pago";
    }
}

// ── 10. INICIALIZACIÓN ────────────────────────────────────────

window.addEventListener("load", () => {
    const pinInput = document.getElementById("pin-input");

    // Enter para confirmar PIN
    pinInput.addEventListener("keydown", e => {
        if (e.key === "Enter") verificarPin();
    });

    // Auto-verificar cuando el input tiene suficiente longitud
    pinInput.addEventListener("input", () => {
        if (pinInput.value.length >= 8) verificarPin();
    });
});
