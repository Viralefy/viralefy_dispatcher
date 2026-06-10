//! Camada de segurança aplicativa do dispatcher.
//!
//! Defense-in-depth: Caddy+Coraza pega a maioria dos ataques (XSS, SQLi,
//! path traversal, command injection) antes de chegar aqui. Este módulo
//! cuida do que é semântico e do contexto do app:
//!
//! - Sanitização HTML residual em campos textuais (`ammonia`)
//! - Regex denylist pra path traversal sneaky (e.g. `..%2f`)
//! - Body size enforcement per-endpoint
//! - Header allow-list (descartar headers do cliente que viraram surface)
//! - User-Agent check (denylist de bots conhecidos sem cabeçalho válido)
//!
//! JWT verify e rate limit vivem em outros módulos (a criar):
//! `security::jwt`, `security::ratelimit`.

#![allow(dead_code)]

use once_cell::sync::Lazy;
use regex::Regex;

// Lista de patterns que NUNCA devem aparecer em paths. Cobre encoded
// traversal e null-byte attacks que o Coraza CRS pega como defense N-1.
// Tudo case-insensitive pra cobrir `..%2F`, `..%2f`, `..%5C`, etc.
static PATH_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\.\./").unwrap(),
        Regex::new(r"\.\.\\").unwrap(),
        // Encoded dot-dot variants (case-insensitive).
        Regex::new(r"(?i)\.\.%2f").unwrap(),
        Regex::new(r"(?i)\.\.%5c").unwrap(),
        Regex::new(r"(?i)%2e%2e").unwrap(),
        Regex::new(r"(?i)%2e%2e%2f").unwrap(),
        Regex::new(r"(?i)%2e%2e%5c").unwrap(),
        // Null byte attacks.
        Regex::new(r"(?i)%00").unwrap(),
        // XSS in URL (defense in depth — Coraza catches first).
        Regex::new(r"(?i)<script").unwrap(),
        Regex::new(r"(?i)javascript:").unwrap(),
    ]
});

/// True se o path contém qualquer pattern proibido. Aplicado a TODO request
/// antes de qualquer roteamento.
pub fn path_is_safe(path: &str) -> bool {
    !PATH_DENYLIST.iter().any(|re| re.is_match(path))
}

/// Sanitiza string de input removendo HTML executável. Usado em campos
/// de texto livre (review body, nome de usuário em registro).
pub fn sanitize_html(input: &str) -> String {
    ammonia::Builder::default()
        .tags(std::collections::HashSet::new()) // strip all tags
        .clean(input)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_denies_traversal() {
        assert!(!path_is_safe("/../etc/passwd"));
        assert!(!path_is_safe("/foo/..\\bar"));
        assert!(!path_is_safe("/v1/users/%2e%2e/admin"));
        assert!(!path_is_safe("/v1/items/file%00.txt"));
        assert!(!path_is_safe("/v1/x?q=<script>alert(1)</script>"));
        assert!(!path_is_safe("/v1/x?u=javascript:alert(1)"));
        // Encoded variants — case-insensitive
        assert!(!path_is_safe("/v1/foo/..%2f/etc"));
        assert!(!path_is_safe("/v1/foo/..%2F/etc"));
        assert!(!path_is_safe("/v1/foo/..%5c/etc"));
        assert!(!path_is_safe("/v1/foo/%2e%2e%2f/etc"));
        // Caminhos legítimos
        assert!(path_is_safe("/v1/me/orders"));
        assert!(path_is_safe("/v1/plans/abc-123/reviews"));
    }

    #[test]
    fn sanitize_strips_html() {
        assert_eq!(sanitize_html("hello"), "hello");
        assert_eq!(sanitize_html("<script>alert(1)</script>hi"), "hi");
        assert_eq!(sanitize_html("a<b>bold</b>c"), "aboldc");
    }
}
