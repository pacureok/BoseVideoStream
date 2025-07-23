// src/app/api/auth/[...nextauth]/route.ts
// Este archivo configura NextAuth.js para manejar la autenticación en tu aplicación Next.js.

import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

// Importa las funciones de autenticación y base de datos desde tus módulos locales.
// Las rutas @/src/lib/auth y @/src/lib/db son alias configurados en tsconfig.json.
import { comparePassword } from "@/src/lib/auth"; // Función para comparar contraseñas hasheadas
import { query } from "@/src/lib/db"; // Función para interactuar con la base de datos

// Define las opciones de autenticación para NextAuth.js
export const authOptions = {
  // Configura los proveedores de autenticación. Aquí usamos CredentialsProvider para usuario/contraseña.
  providers: [
    CredentialsProvider({
      name: "Credentials", // Nombre que se mostrará en la interfaz de inicio de sesión
      // Define los campos de credenciales que se esperan del formulario de inicio de sesión.
      credentials: {
        username: { label: "Username", type: "text" },
        password: { label: "Password", type: "password" },
      },
      // La función 'authorize' se ejecuta cuando un usuario intenta iniciar sesión.
      // Aquí es donde verificas las credenciales contra tu base de datos.
      async authorize(credentials, req) {
        // Verifica si se proporcionaron el nombre de usuario y la contraseña.
        if (!credentials?.username || !credentials.password) {
          return null; // Si faltan credenciales, retorna null (fallo de autenticación)
        }

        // Consulta la base de datos para encontrar al usuario por su nombre de usuario.
        const userRes = await query("SELECT id, username, password, is_creator FROM users WHERE username = $1", [credentials.username]);
        const user = userRes.rows[0]; // Obtiene el primer resultado (el usuario)

        // Si el usuario no existe o la contraseña no coincide, retorna null.
        // 'comparePassword' compara la contraseña proporcionada con la contraseña hasheada en la base de datos.
        if (!user || !(await comparePassword(credentials.password, user.password))) {
          return null; // Usuario o contraseña incorrectos
        }

        // Si la autenticación es exitosa, retorna un objeto de usuario.
        // Este objeto se serializará en el token JWT y la sesión.
        return {
          id: user.id,
          name: user.username,
          isCreator: user.is_creator, // Añadimos si el usuario es un creador
        };
      },
    }),
  ],
  // Define las rutas personalizadas para las páginas de autenticación.
  pages: {
    signIn: "/login", // Ruta a tu página de inicio de sesión
    error: "/login", // Ruta a la página de error de inicio de sesión
  },
  // Define las funciones de callback para personalizar el comportamiento de JWT y la sesión.
  callbacks: {
    // El callback 'jwt' se ejecuta cuando se crea o actualiza un token JWT.
    // Aquí puedes añadir información adicional del usuario al token.
    async jwt({ token, user }) {
      if (user) {
        // Si hay un objeto de usuario (después de una autenticación exitosa),
        // añade 'id' y 'isCreator' al token.
        token.id = user.id;
        token.isCreator = user.isCreator;
      }
      return token; // Retorna el token modificado
    },
    // El callback 'session' se ejecuta cuando se crea una sesión.
    // Aquí puedes añadir información del token a la sesión.
    async session({ session, token }) {
      // Añade 'id' y 'isCreator' del token a la sesión del usuario.
      session.user.id = token.id;
      session.user.isCreator = token.isCreator;
      return session; // Retorna el objeto de sesión modificado
    },
  },
  // Define la clave secreta para firmar y cifrar los tokens JWT.
  // Es crucial que esta variable de entorno (NEXTAUTH_SECRET) sea segura y se mantenga en secreto.
  secret: process.env.NEXTAUTH_SECRET,
};

// Crea el manejador de NextAuth con las opciones definidas.
const handler = NextAuth(authOptions);

// Exporta los manejadores GET y POST para que Next.js los use como rutas API.
// Esto permite que NextAuth.js maneje las solicitudes de autenticación.
export { handler as GET, handler as POST };
