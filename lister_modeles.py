"""
Inventaire des modèles du serveur d'inférence.

Le serveur est mutualisé et évince les modèles inactifs. Un modèle absent de la
mémoire doit être rechargé intégralement avant la première réponse, et ce
chargement domine tout le reste : quinze gigaoctets ne se chargent pas comme
quatre. C'est la cause la plus fréquente d'un assistant qui semble ne pas
répondre.

Ce script dit ce qui est disponible, ce qui est chargé à l'instant, et où se
situe le modèle configuré. L'option --mesurer chronomètre en plus une vraie
question de sécurité en français, chargement compris.

Usage, depuis le dossier backend/ :
    python lister_modeles.py
    python lister_modeles.py --mesurer            tous les modèles, long
    python lister_modeles.py --mesurer mistral:latest gemma3:12b
"""

import sys
import time

import httpx

from config import OLLAMA_KEY, OLLAMA_MODEL, OLLAMA_URL

ENTETES = {"Authorization": f"Bearer {OLLAMA_KEY}"}

# Le chargement d'un modèle de plusieurs gigaoctets prend parfois plusieurs
# minutes sur une machine partagée : un délai serré ferait conclure à une panne.
DELAI = httpx.Timeout(connect=15.0, read=420.0, write=15.0, pool=5.0)

QUESTION = ("Tu es un expert en cybersécurité. Un domaine sénégalais n'a pas "
            "d'enregistrement SPF. Explique en trois phrases simples le risque "
            "encouru et comment le corriger.")


def _get(chemin: str) -> dict:
    reponse = httpx.get(f"{OLLAMA_URL}{chemin}", headers=ENTETES, timeout=DELAI)
    reponse.raise_for_status()
    return reponse.json()


def disponibles() -> list[dict]:
    return sorted(_get("/api/tags").get("models", []), key=lambda m: m.get("size", 0))


def charges() -> list[str]:
    return [m.get("model") or m.get("name") for m in _get("/api/ps").get("models", [])]


def generer(modele: str, prompt: str, jetons: int = 180) -> tuple[float, str]:
    debut = time.perf_counter()
    reponse = httpx.post(
        f"{OLLAMA_URL}/api/generate", headers=ENTETES, timeout=DELAI,
        json={"model": modele, "prompt": prompt, "stream": False, "think": False,
              "keep_alive": "10m",
              "options": {"num_predict": jetons, "temperature": 0.6}},
    )
    reponse.raise_for_status()
    return time.perf_counter() - debut, reponse.json().get("response", "").strip()


def inventaire() -> None:
    try:
        modeles = disponibles()
        en_memoire = charges()
    except Exception as e:
        print(f"  serveur injoignable : {type(e).__name__}")
        return

    print(f"  {len(modeles)} modèle(s) disponible(s) sur {OLLAMA_URL}\n")
    print("  " + "modèle".ljust(30) + "taille".rjust(9) + "  paramètres  quantif.   état")
    for m in modeles:
        nom = m.get("model", "")
        detail = m.get("details", {}) or {}
        etat = "en mémoire" if nom in en_memoire else ""
        if nom == OLLAMA_MODEL:
            etat = (etat + " · configuré").strip(" ·")
        print("  " + nom[:29].ljust(30)
              + f"{m.get('size', 0) / 1e9:.1f} Go".rjust(9)
              + "  " + str(detail.get("parameter_size", "?")).rjust(10)
              + "  " + str(detail.get("quantization_level", "?")).ljust(9)
              + "  " + etat)

    if not en_memoire:
        print("\n  Aucun modèle en mémoire : la prochaine réponse paiera le")
        print("  chargement complet, d'autant plus long que le modèle est lourd.")


def mesurer(noms: list[str]) -> None:
    """Chronomètre chaque modèle sur une vraie question, chargement compris.

    Deux temps sont relevés : la première réponse, qui inclut le chargement et
    correspond à ce que vit le premier client de la journée, puis une seconde
    requête, qui donne le régime de croisière."""
    for nom in noms:
        print(f"\n=== {nom}")
        try:
            froid, texte = generer(nom, QUESTION)
            chaud, _ = generer(nom, "Dis bonjour en un mot.", 10)
            print(f"    première réponse, chargement compris : {froid:.0f} s")
            print(f"    réponse suivante, modèle en mémoire  : {chaud:.1f} s")
            print("    extrait : " + " ".join(texte.split())[:260])
        except httpx.TimeoutException:
            print("    ÉCHEC : pas de réponse en 7 minutes, modèle trop lourd")
            print("            pour la charge actuelle du serveur")
        except Exception as e:
            print(f"    ÉCHEC : {type(e).__name__}")


if __name__ == "__main__":
    print("=== Modèles du serveur d'inférence ===\n")
    inventaire()
    if "--mesurer" in sys.argv:
        demandes = [a for a in sys.argv[sys.argv.index("--mesurer") + 1:]
                    if not a.startswith("-")]
        if not demandes:
            demandes = [m.get("model") for m in disponibles()
                        if m.get("size", 0) > 1e9]
        print("\n\n=== Mesures ===")
        print("  Une question de sécurité en français, en conditions réelles.")
        mesurer(demandes)
