const express = require('express');
const app = express();

// ===== CONFIGURAÇÕES =====
const TOKEN_VALIDO = 'testeAPI';
const PORTA = 3000;
const HOST = '0.0.0.0'; 

// ===== ROTA PRINCIPAL =====
app.get('/api/verificar-acesso', (req, res) => {
    // Pega o token enviado pelo ESP32
    const token = req.headers['authorization'];
    const lockId = req.headers['x-lock-id'];
    
    console.log('Recebeu requisição:');
    console.log('  Token:', token);
    console.log('  Fechadura:', lockId);
    
    // Valida o token
    if (token !== 'Bearer ' + TOKEN_VALIDO) {
        console.log('❌ Token inválido!');
        // Inclui log útil para o ambiente de teste
        console.log(`Token esperado: Bearer ${TOKEN_VALIDO}, Recebido: ${token}`); 
        return res.status(401).json({ permitido: false }); // Retorna 401 (Não Autorizado)
    }
    
    // ✅ TUDO CERTO - Libera acesso
    console.log('✅ Acesso permitido!');
    res.json({ permitido: true });
});

// ===== INICIA O SERVIDOR =====
// Agora passamos o HOST (0.0.0.0) para que ele escute em todos os IPs
app.listen(PORTA, HOST, () => {
    console.log('');
    console.log('🚀 API está rodando!');
    console.log('🌐 Endereço de Escuta (HOST):', HOST);
    console.log('🌐 Porta:', PORTA);
    console.log('');
});