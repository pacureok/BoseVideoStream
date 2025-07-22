'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function RegisterPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (res.ok) {
      router.push('/login'); // Redirige a la página de inicio de sesión
    } else {
      const data = await res.json();
      setError(data.message || 'Error al registrar.');
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '50px auto', padding: '20px', backgroundColor: '#2a2a2a', borderRadius: '8px' }}>
      <h2>Registrarse en BoseVideoStream</h2>
      {error && <p style={{ color: 'red', textAlign: 'center' }}>{error}</p>}
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <label>
          Usuario:
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label>
          Contraseña:
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        <button type="submit" style={{ backgroundColor: '#00e676', color: 'white', padding: '10px', borderRadius: '5px', border: 'none', cursor: 'pointer' }}>Registrarse</button>
      </form>
      <p style={{ textAlign: 'center', marginTop: '20px' }}>¿Ya tienes cuenta? <a href="/login">Inicia sesión</a></p>
    </div>
  );
}
