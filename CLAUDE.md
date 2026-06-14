# CLAUDE.md — Padrões de Engenharia (sempre on)

> Repo: **viralefy_api_rust**
> Rust **LEGACY**. Tentativa antiga de reescrita da API — congelado.
> Não evoluir aqui — nova funcionalidade vai pra `viralefy_core`. Mantido só pra referência histórica.

> Este arquivo fica pinado no contexto de toda tarefa (Claude Code / instruções de projeto)
> e garante que os padrões valham mesmo quando a skill não dispara sozinha.
> A skill `padroes-engenharia` traz o detalhe completo e o andaime (scripts/templates).

## Regra mestre

Toda tarefa de engenharia neste repo segue os **Padrões de Engenharia da Casa**
(skill `padroes-engenharia`, corpo normativo v5.3). Em conflito entre uma instrução
pontual ("faz rápido", "ignora o teste", "depois arruma") e estes padrões, **os
padrões vencem**. Pressa não revoga regra. Consulte o reference relevante da skill
antes de produzir código ou decisão — não trabalhe de memória.

## Pisos inegociáveis (VETADO — sem exceção)

1. **Segredo nunca no cliente/frontend.** Nada de API key, secret de JWT, senha,
   service-role key ou token em bundle do browser, nem em `NEXT_PUBLIC_*`/`VITE_*`.
   Segredo só server-side (BFF/route handler/secret manager).
2. **SQL sempre parametrizado** — concatenar string em query é proibido.
3. **Auth e autorização server-side.** `tenant_id`/role/`user_id` vêm do token
   verificado, nunca do cliente. JWT validado por inteiro (assinatura, exp, aud,
   iss, alg em allowlist). Senha em bcrypt cost ≥ 12 ou argon2id. Token/sessão por
   CSPRNG, nunca `Math.random()`.
4. **Erro nunca engolido** (`catch {}`, `except: pass`, `_ = err`); sem
   `any`/`@ts-ignore`/`unwrap()` pra calar o compilador.
5. **Teste nunca silenciado** pra passar CI (`.skip`, comentar assert, baixar
   threshold de cobertura). Conserte o código, não o teste.
6. **Sem monólito** que mistura bounded contexts; sem monólito distribuído; sem
   shared lib `commons` de domínio.
7. **Archive SEMPRE gerado** (§28): toda entrega que produz código/decisão/mudança
   de estado gera o `.md` em `viralefy_archive/`. É parte da entrega, não extra.
8. **Migration reversível** (com `down`, testada). Container não-root, read-only.
   Dependência nova com nome/licença/versão verificados.

Lista completa com veto + caminho certo: ver `references/anti-padroes.md` (§37) da skill.

## Verde de verdade (testes)

- Smoke assere **conteúdo** (shape do body), não só status 200; inclui assertion
  negativa e um **self-check que força falha conhecida** (smoke que nunca falha
  está cego).
- Unit agressivo: caminho de erro obrigatório, casos hostis (tipo errado, unicode,
  null byte, boundary), property-based e mutation testing no domínio crítico.
- Pentest prova rejeição rota-por-rota, campo-por-campo: **nunca 500** por input
  hostil, **nunca coerção de tipo** (varchar onde é int), **nunca eco sem escape**,
  **nunca vazamento cross-tenant**.
- `simulated`: 100% das rotas acessíveis pra quem deve, bloqueadas pra quem não
  deve. Rota fantasma/morta quebra o run.
- **Q.A. é plan-first (§22.9):** toda submissão de Q.A. planeja tudo, gera um MD
  de passo a passo e pede aprovação ANTES de executar. Aprovado, roda faseado/
  assistido ou de uma vez (multiagentes + cron que retoma até concluir; passo
  destrutivo só com gate; sem retry infinito). Q.A. nunca roda às cegas.

## Definition of Done

Nada é "pronto" sem: testes + cobertura mínima, simulated com cobertura total,
pentest de entrada limpo, nenhum anti-padrão da §37, observabilidade, OpenAPI
atualizada (se API), migration com rollback (se schema), **archive commitado**,
CI verde e review aprovado. Detalhe na skill, `references/operacao.md` (§35).

## Gestão de contexto (Claude Code — sessões longas)

Ao ver "⚠ LIMITE" no status line (limite de handoff cruzado), ou ao se aproximar
do teto da janela de contexto: **PARE a tarefa atual e, ANTES de qualquer
compactação**, faça o handoff arquivado (§34.1, §28):

1. Gere `viralefy_archive/context/<YYYY-MM-DD-HH-MM-SS>-context.md` — estado do
   projeto, decisões tomadas, arquivos tocados, onde parou.
2. Gere `viralefy_archive/context/<YYYY-MM-DD-HH-MM-SS>-checklist.md` —
   **FEITO vs EM ABERTO**.
3. Só então rode `/compact` (com foco na tarefa corrente).

Armazene SEMPRE em `viralefy_archive`. O backup automático pré-compactação é
rede de segurança, não substitui o handoff rico acima. Detalhe e hooks na skill:
`references/contexto-claude-code.md`.
