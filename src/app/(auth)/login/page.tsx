'use client';
import { useState } from 'react';
import { signIn } from 'next-auth/react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get('callbackUrl') || '/';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const result = await signIn('credentials', {
      redirect: false,
      username,
      password,
    });

    if (result?.error) {
      setError('Usuario o contraseña incorrectos.');
    } else if (result?.ok) {
      router.push(callbackUrl);
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '50px auto', padding: '20px', backgroundColor: '#2a2a2a', borderRadius: '8px' }}>
      <h2>Iniciar Sesión en BoseVideoStream</h2>
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
        <button type="submit" style={{ backgroundColor: '#007bff', color: 'white', padding: '10px', borderRadius: '5px', border: 'none', cursor: 'pointer' }}>Iniciar Sesión</button>
      </form>
      <p style={{ textAlign: 'center', marginTop: '20px' }}>¿No tienes cuenta? <a href="/register">Regístrate aquí</a></p>
    </div>
  );
}
