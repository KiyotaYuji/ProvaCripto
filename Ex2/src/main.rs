// Constantes para o SHA-256

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const BASE_PATH: &str = r"C:\Users\YujiKiyota\OneDrive\Área de Trabalho\Faculdade\Quinto Periodo\Cripto\marco-19\arquivos";

fn Caminho(nomeArquivo: &str) -> std::path::PathBuf{
    let mut caminho = std::path::PathBuf::from(BASE_PATH);
    caminho.push(nomeArquivo);
    caminho
}
fn lerArquivos(caminho: &Path) -> io::Result<Vec<u8>> {
    let mut arquivo = File::open(caminho)?;
    let mut buffer = Vec::new();
    arquivo.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn calculoHash(caminho: &Path) -> io::Result<[u8; 32]> {
    let conteudo = lerArquivos(caminho)?;
    Ok(sha256(&conteudo))
}
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

fn main() {
    let mut continuar = true;

    while continuar {
        println!("Escolha uma opção:");
        println!("1 - Calcular hash de texto");
        println!("2 - Calcular hash de arquivo");
        println!("3 - Comparar hashes de dois arquivos");
        println!("4 - Verificar hash de arquivo");
        println!("5 - Sair");

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
                println!("Digite o texto para calcular o hash SHA-256:");
                let mut texto = String::new();
                io::stdin().read_line(&mut texto).expect("Falha ao ler a entrada");
                let hash = sha256(texto.trim().as_bytes());
                println!("SHA-256: {}", bytes_to_hex_string(&hash));
            },
            2 => {
                println!("Digite apenas o nome do arquivo (ex: Pedro.png):");
                let mut nomeArquivo = String::new();
                io::stdin().read_line(&mut nomeArquivo).expect("Falha ao ler o nome");
                let caminho = Caminho(nomeArquivo.trim());

                if !caminho.exists() {
                    println!("Erro: O arquivo '{}' não existe.", caminho.display());
                    continue;
                }

                match calculoHash(&caminho) {
                    Ok(hash) => {
                        println!("Arquivo: {}", caminho.display());
                        println!("SHA-256: {}", bytes_to_hex_string(&hash));
                    },
                    Err(erro) => {
                        println!("Erro ao processar o arquivo: {}", erro);
                    }
                }
            },
            3 => {
                println!("Digite apenas o nome do primeiro arquivo:");
                let mut nome_arquivo1 = String::new();
                io::stdin().read_line(&mut nome_arquivo1).expect("Falha ao ler o nome");
                let caminho1 = Caminho(nome_arquivo1.trim());

                println!("Digite apenas o nome do segundo arquivo:");
                let mut nome_arquivo2 = String::new();
                io::stdin().read_line(&mut nome_arquivo2).expect("Falha ao ler o nome");
                let caminho2 = Caminho(nome_arquivo2.trim());

                if !caminho1.exists() {
                    println!("Erro: O arquivo '{}' não existe.", caminho1.display());
                    continue;
                }
                if !caminho2.exists() {
                    println!("Erro: O arquivo '{}' não existe.", caminho2.display());
                    continue;
                }

                match (calculoHash(&caminho1), calculoHash(&caminho2)) {
                    (Ok(hash1), Ok(hash2)) => {
                        println!("Arquivo 1: {}", caminho1.display());
                        println!("SHA-256: {}", bytes_to_hex_string(&hash1));
                        println!("Arquivo 2: {}", caminho2.display());
                        println!("SHA-256: {}", bytes_to_hex_string(&hash2));

                        if hash1 == hash2 {
                            println!("Os arquivos são idênticos (hashes iguais).");
                        } else {
                            println!("Os arquivos são diferentes (hashes diferentes).");
                        }
                    },
                    _ => println!("Erro ao calcular o hash de um dos arquivos.")
                }
            },
            4 => {
                println!("Digite apenas o nome do arquivo:");
                let mut nome_arquivo = String::new();
                io::stdin().read_line(&mut nome_arquivo).expect("Falha ao ler o nome");
                let caminho = Caminho(nome_arquivo.trim());

                println!("Digite o hash SHA-256 esperado:");
                let mut hash_esperado_str = String::new();
                io::stdin().read_line(&mut hash_esperado_str).expect("Falha ao ler o hash");
                let hash_esperado_str = hash_esperado_str.trim();

                if !caminho.exists() {
                    println!("Erro: O arquivo '{}' não existe.", caminho.display());
                    continue;
                }

                match calculoHash(&caminho) {
                    Ok(hash) => {
                        let hash_str = bytes_to_hex_string(&hash);
                        println!("Arquivo: {}", caminho.display());
                        println!("SHA-256 calculado: {}", hash_str);
                        println!("SHA-256 esperado:  {}", hash_esperado_str);

                        if hash_str.eq_ignore_ascii_case(hash_esperado_str) {
                            println!("Verificação bem-sucedida! O hash coincide.");
                        } else {
                            println!("Falha na verificação! Os hashes são diferentes.");
                        }
                    },
                    Err(erro) => {
                        println!("Erro ao processar o arquivo: {}", erro);
                    }
                }
            },
            5 => {
                println!("Saindo do programa...");
                continuar = false;
            },
            _ => println!("Opção inválida! Por favor escolha um número entre 1 e 5.")
        }

        if continuar {
            println!("\n");
        }
    }
}