import bcrypt from 'bcrypt';

// Función para hashear la contraseña 
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

// Función para comparar contraseñas
export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

// --- Simulación de funciones que no usarán 2FA ---
// La lógica de NextAuth se encargará del token JWT de sesión.
// No necesitamos speakeasy si no hay 2FA.
