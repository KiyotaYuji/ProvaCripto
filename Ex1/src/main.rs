use std::io::{self};
use std::path::Path;
use std::fs::File;
use std::io::Read;

// Constantes para o SHA-256
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// Valores iniciais de hash
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

// Funções para Base64
fn base64_encode(input: &[u8]) -> String {
    // Tabela de caracteres Base64
    let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();

    // Processa os dados de 3 em 3 bytes, pois 3 bytes (24 bits) = 4 caracteres (4*6 bits)
    for chunk in input.chunks(3) {
        let mut buf: u32 = 0;

        // Combina 3 bytes (ou menos) em um valor de 24 bits
        for (i, &b) in chunk.iter().enumerate() {
            buf |= (b as u32) << (16 - i * 8);
        }

        // Extrai 4 índices de 6 bits para usar na tabela
        let indices = [
            (buf >> 18) & 0x3F,
            (buf >> 12) & 0x3F,
            (buf >> 6) & 0x3F,
            buf & 0x3F
        ];

        // Adiciona os caracteres correspondentes
        result.push(base64_chars.chars().nth(indices[0] as usize).unwrap());
        result.push(base64_chars.chars().nth(indices[1] as usize).unwrap());

        // Adiciona o restante dos caracteres ou padding
        if chunk.len() > 1 {
            result.push(base64_chars.chars().nth(indices[2] as usize).unwrap());
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(base64_chars.chars().nth(indices[3] as usize).unwrap());
        } else {
            result.push('=');
        }
    }

    result
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, String> {
    // Tabela de caracteres Base64
    let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut bytes: Vec<u8> = Vec::new();
    let encoded_chars: Vec<char> = encoded.chars().collect();

    // Processa os dados em grupos de 4 caracteres
    for chunk in encoded_chars.chunks(4) {
        // Converte os caracteres para índices na tabela
        let mut indices: [i32; 4] = [0, 0, 0, 0];

        for (i, &ch) in chunk.iter().enumerate() {
            if ch == '=' {
                indices[i] = -1; // Marca padding
            } else {
                if let Some(pos) = base64_chars.find(ch) {
                    indices[i] = pos as i32;
                } else {
                    return Err(format!("Caractere inválido encontrado: {}", ch));
                }
            }
        }

        // Combina os índices em bytes
        let mut buf: u32 = 0;
        let mut bytes_to_add = 3;

        // Monta o valor de 24 bits
        for i in 0..4 {
            if indices[i] >= 0 {
                buf = (buf << 6) | (indices[i] as u32);
            } else {
                buf <<= 6;
                bytes_to_add -= 1;
            }
        }

        // Extrai os bytes
        if bytes_to_add >= 1 {
            bytes.push(((buf >> 16) & 0xFF) as u8);
        }
        if bytes_to_add >= 2 {
            bytes.push(((buf >> 8) & 0xFF) as u8);
        }
        if bytes_to_add >= 3 {
            bytes.push((buf & 0xFF) as u8);
        }
    }

    Ok(bytes)
}

// Funções para SHA-256
// Rotação à direita (circular right shift)
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

// Funções auxiliares SHA-256
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn gamma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn gamma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// Processar um bloco de mensagem
fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];

    // Preparar a agenda de mensagem
    for i in 0..16 {
        w[i] = ((block[i * 4] as u32) << 24) |
            ((block[i * 4 + 1] as u32) << 16) |
            ((block[i * 4 + 2] as u32) << 8) |
            (block[i * 4 + 3] as u32);
    }

    for i in 16..64 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    // Inicializar registros de trabalho com o valor atual do hash
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Compressão principal
    for i in 0..64 {
        let t1 = h.wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Adicionar os valores comprimidos ao estado atual
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// Função principal SHA-256
fn sha256(message: &[u8]) -> [u8; 32] {
    // Inicializar valores de hash
    let mut state = H_INIT;

    // Pré-processamento: preenchimento da mensagem
    let len = message.len();
    let bit_len = (len * 8) as u64;

    // Calcular o número de bytes necessários para o padding
    let mut padded_message = Vec::with_capacity(len + 9 + (64 - ((len + 9) % 64)) % 64);
    padded_message.extend_from_slice(message);

    // Adicionar bit '1' seguido por zeros
    padded_message.push(0x80);

    // Calcular quantos zeros adicionar antes do comprimento da mensagem
    let padding_zeros = (64 - ((len + 1 + 8) % 64)) % 64;
    padded_message.extend(vec![0; padding_zeros]);

    // Adicionar o comprimento da mensagem em bits como um inteiro de 64 bits big-endian
    padded_message.extend_from_slice(&[
        ((bit_len >> 56) & 0xff) as u8,
        ((bit_len >> 48) & 0xff) as u8,
        ((bit_len >> 40) & 0xff) as u8,
        ((bit_len >> 32) & 0xff) as u8,
        ((bit_len >> 24) & 0xff) as u8,
        ((bit_len >> 16) & 0xff) as u8,
        ((bit_len >> 8) & 0xff) as u8,
        (bit_len & 0xff) as u8,
    ]);

    // Processar a mensagem em blocos de 64 bytes
    for chunk in padded_message.chunks(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        process_block(&mut state, &block);
    }

    // Produzir o hash final
    let mut hash = [0u8; 32];
    for i in 0..8 {
        hash[i*4] = ((state[i] >> 24) & 0xff) as u8;
        hash[i*4 + 1] = ((state[i] >> 16) & 0xff) as u8;
        hash[i*4 + 2] = ((state[i] >> 8) & 0xff) as u8;
        hash[i*4 + 3] = (state[i] & 0xff) as u8;
    }

    hash
}

// Converte um array de bytes para string hexadecimal
fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// Funções para autenticação de mensagens
fn codificar_mensagem_autenticada(texto: &str, chave: &str) -> String {
    // Etapa 1: Codificar o conteúdo em Base64
    let conteudo_codificado = base64_encode(texto.as_bytes());

    // Etapa 2: Gerar HMAC-SHA256 para autenticação
    // Aqui implementamos um HMAC simples concatenando chave+mensagem para o hash
    let hmac_input = format!("{}{}", chave, texto);
    let hmac = sha256(hmac_input.as_bytes());
    let hmac_hex = bytes_to_hex_string(&hmac);

    // Etapa 3: Retornar mensagem no formato "conteudoBase64:hmacHex"
    format!("{}:{}", conteudo_codificado, hmac_hex)
}

fn decodificar_mensagem_autenticada(mensagem_codificada: &str, chave: &str) -> Result<String, String> {
    // Separar a mensagem codificada do HMAC
    let partes: Vec<&str> = mensagem_codificada.split(':').collect();
    if partes.len() != 2 {
        return Err("Formato inválido: A mensagem deve estar no formato 'conteudoBase64:hmacHex'".to_string());
    }

    let conteudo_base64 = partes[0];
    let hmac_recebido = partes[1];

    // Decodificar o conteúdo
    let bytes_decodificados = match base64_decode(conteudo_base64) {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("Erro ao decodificar Base64: {}", e)),
    };

    let texto_original = match String::from_utf8(bytes_decodificados.clone()) {
        Ok(s) => s,
        Err(_) => return Err("Erro ao converter bytes decodificados para UTF-8".to_string()),
    };

    // Verificar autenticidade
    let hmac_input = format!("{}{}", chave, texto_original);
    let hmac_calculado = sha256(hmac_input.as_bytes());
    let hmac_calculado_hex = bytes_to_hex_string(&hmac_calculado);

    if hmac_calculado_hex != hmac_recebido {
        return Err("Autenticação falhou: A mensagem pode ter sido adulterada".to_string());
    }

    // Se chegou aqui, a mensagem é autêntica
    Ok(texto_original)
}

fn main() {
    let mut continuar = true;

    while continuar {
        println!("\n=== Sistema de Comunicação Segura ===");
        println!("Escolha uma opção:");
        println!("1 - Codificar mensagem (permite autenticação)");
        println!("2 - Decodificar e verificar mensagem");
        println!("3 - Sair");

        let mut escolha = String::new();
        io::stdin().read_line(&mut escolha).expect("Falha ao ler a entrada");
        let escolha: u32 = match escolha.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Entrada inválida! Por favor digite um número.");
                continue;
            }
        };

        match escolha {
            1 => {
                println!("Digite a mensagem a ser codificada:");
                let mut texto = String::new();
                io::stdin().read_line(&mut texto).expect("Falha ao ler a entrada");
                let texto = texto.trim();

                println!("Digite a chave secreta para autenticação:");
                let mut chave = String::new();
                io::stdin().read_line(&mut chave).expect("Falha ao ler a entrada");
                let chave = chave.trim();

                let mensagem_codificada = codificar_mensagem_autenticada(texto, chave);
                println!("\nMensagem codificada com autenticação:");
                println!("{}", mensagem_codificada);
            },
            2 => {
                println!("Digite a mensagem codificada (formato 'conteudoBase64:hmacHex'):");
                let mut mensagem_codificada = String::new();
                io::stdin().read_line(&mut mensagem_codificada).expect("Falha ao ler a entrada");
                let mensagem_codificada = mensagem_codificada.trim();

                println!("Digite a chave secreta para verificação:");
                let mut chave = String::new();
                io::stdin().read_line(&mut chave).expect("Falha ao ler a entrada");
                let chave = chave.trim();

                match decodificar_mensagem_autenticada(mensagem_codificada, chave) {
                    Ok(texto_original) => {
                        println!("\nMensagem verificada e autêntica!");
                        println!("Conteúdo original: {}", texto_original);
                    },
                    Err(erro) => println!("\nErro: {}", erro),
                }
            },
            3 => {
                println!("Saindo do programa...");
                continuar = false;
            },
            _ => println!("Opção inválida! Por favor escolha um número entre 1 e 3."),
        }
    }
}