"""
Accès au modèle de langage, avec repli.

Le serveur d'inférence de l'UN-CHK est gratuit et garde les données de nos
clients au Sénégal : il reste la source première. Mais il est mutualisé, et
deux pannes prolongées ont été constatées en deux jours — l'API répondait en
moins d'une seconde tandis qu'aucune génération n'aboutissait, pas même un
jeton unique sur un modèle déjà résident.

Un secours prend le relais lorsqu'il ne répond pas. Il n'est sollicité que
dans ce cas : les invites contiennent les ports ouverts, les CVE et les secrets
exposés des actifs d'un client, et ces données ne doivent pas quitter le pays
sans nécessité.

Le secours parle le dialecte OpenAI, que presque tous les fournisseurs
exposent — Mistral, Groq, OpenAI, OpenRouter, et Gemini par son point d'entrée
de compatibilité. Trois variables suffisent donc à en changer, sans toucher au
code :

    LLM_SECOURS_URL     https://api.mistral.ai/v1
    LLM_SECOURS_KEY     la clé du fournisseur
    LLM_SECOURS_MODEL   mistral-small-latest

Sans ces variables, le comportement est inchangé : Ollama seul.
"""

import json
from typing import Iterator

import httpx

from config import (LLM_SECOURS_KEY, LLM_SECOURS_MODEL, LLM_SECOURS_URL,
                    OLLAMA_KEEP_ALIVE, OLLAMA_KEY, OLLAMA_MODEL, OLLAMA_URL)

# Le serveur mutualisé a été chronométré entre 0,6 et 139 secondes selon sa
# charge. Le délai de lecture reste large pour ne pas abandonner une génération
# qui aboutirait, mais borné pour que le repli ait une chance de servir.
DELAI = httpx.Timeout(connect=15.0, read=180.0, write=15.0, pool=5.0)
DELAI_SECOURS = httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=5.0)


def secours_configure() -> bool:
    return bool(LLM_SECOURS_URL and LLM_SECOURS_KEY and LLM_SECOURS_MODEL)


# ── Source première : Ollama ──────────────────────────────────────────────────

def _ollama(prompt: str, jetons: int) -> str:
    reponse = httpx.post(
        f"{OLLAMA_URL}/api/generate",
        headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
              "keep_alive": OLLAMA_KEEP_ALIVE, "think": False,
              "options": {"num_predict": jetons, "temperature": 0.6}},
        timeout=DELAI,
    )
    reponse.raise_for_status()
    return (reponse.json().get("response") or "").strip()


def _ollama_flux(prompt: str, jetons: int) -> Iterator[str]:
    with httpx.stream(
        "POST", f"{OLLAMA_URL}/api/generate",
        headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": True,
              "keep_alive": OLLAMA_KEEP_ALIVE, "think": False,
              "options": {"num_predict": jetons, "temperature": 0.6}},
        timeout=DELAI,
    ) as reponse:
        reponse.raise_for_status()
        for ligne in reponse.iter_lines():
            if not ligne:
                continue
            morceau = json.loads(ligne)
            if morceau.get("response"):
                yield morceau["response"]
            if morceau.get("done"):
                return


# ── Secours : dialecte OpenAI ─────────────────────────────────────────────────

def _secours(prompt: str, jetons: int) -> str:
    reponse = httpx.post(
        f"{LLM_SECOURS_URL.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {LLM_SECOURS_KEY}",
                 "Content-Type": "application/json"},
        json={"model": LLM_SECOURS_MODEL,
              "messages": [{"role": "user", "content": prompt}],
              "max_tokens": jetons, "temperature": 0.6},
        timeout=DELAI_SECOURS,
    )
    reponse.raise_for_status()
    choix = reponse.json().get("choices") or [{}]
    return (choix[0].get("message", {}).get("content") or "").strip()


def _secours_flux(prompt: str, jetons: int) -> Iterator[str]:
    with httpx.stream(
        "POST", f"{LLM_SECOURS_URL.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {LLM_SECOURS_KEY}",
                 "Content-Type": "application/json"},
        json={"model": LLM_SECOURS_MODEL,
              "messages": [{"role": "user", "content": prompt}],
              "max_tokens": jetons, "temperature": 0.6, "stream": True},
        timeout=DELAI_SECOURS,
    ) as reponse:
        reponse.raise_for_status()
        for ligne in reponse.iter_lines():
            if not ligne or not ligne.startswith("data:"):
                continue
            charge = ligne[5:].strip()
            if charge == "[DONE]":
                return
            try:
                delta = json.loads(charge)["choices"][0].get("delta", {})
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
            if delta.get("content"):
                yield delta["content"]


# ── Interface publique ────────────────────────────────────────────────────────

def generer(prompt: str, jetons: int = 400) -> str:
    """Texte complet. Chaîne vide si aucune source n'aboutit : l'appelant
    traite ce cas, une notification ou un rapport ne doit jamais échouer parce
    que la rédaction manque."""
    try:
        texte = _ollama(prompt, jetons)
        if texte:
            return texte
        raise RuntimeError("réponse vide")
    except Exception as e:
        if not secours_configure():
            print(f"  [!] modèle indisponible et aucun secours configuré : {e}")
            return ""
        print(f"  [!] source première indisponible ({type(e).__name__}), passage au secours")

    try:
        return _secours(prompt, jetons)
    except Exception as e:
        print(f"  [!] secours indisponible également : {type(e).__name__} : {e}")
        return ""


def generer_flux(prompt: str, jetons: int = 500) -> Iterator[str]:
    """Jetons au fil de l'eau, pour l'assistant conversationnel.

    Le repli n'a lieu qu'avant le premier jeton : une fois le texte commencé,
    basculer de source produirait deux débuts de réponse cousus l'un à
    l'autre, ce qui se voit."""
    commence = False
    try:
        for jeton in _ollama_flux(prompt, jetons):
            commence = True
            yield jeton
        if commence:
            return
        raise RuntimeError("flux vide")
    except Exception as e:
        if commence:
            return          # interrompu en cours de route, on garde l'acquis
        if not secours_configure():
            raise
        print(f"  [!] flux indisponible ({type(e).__name__}), passage au secours")

    yield from _secours_flux(prompt, jetons)
