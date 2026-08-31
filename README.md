# Signalis — Cybersecurity Trend Predictor

Voorspelt de ontwikkeling van cybersecurity-toolcategorieën op basis van
historisch, aggregaat gedrag (CVE-publicatieritme, seizoenspatronen,
adoptiecurves). Geen glazen bol — een extrapolatie van patronen die
historisch stabiel genoeg zijn om te modelleren.

## Structuur

```
cybersec-predict/
├── deploy.sh              Productie-installatie: venv + systemd, poort 4444
├── backend/
│   ├── main.py             FastAPI-server met voorspelmodel
│   │                       (serveert ook de frontend mee onder /app/)
│   └── requirements.txt
└── frontend/
    └── index.html          Dashboard (geen build-stap nodig)
```

Alles draait op **één poort: 4444**. Geen aparte webserver nodig — de
FastAPI-app serveert zowel de API (`/api/...`) als het dashboard (`/app/...`,
met een redirect vanaf `/`) vanuit hetzelfde proces.

## Productie-installatie (aanbevolen): `deploy.sh`

Op een Linux-server met systemd:

```bash
chmod +x deploy.sh
sudo ./deploy.sh
```

Dit doet, idempotent (veilig om opnieuw te draaien bij updates):

1. Maakt een dedicated systeemgebruiker `signalis` aan (geen login/shell).
2. Kopieert het project naar `/opt/cybersec-predict`.
3. Zet een Python-venv op in `/opt/cybersec-predict/venv` en installeert
   `requirements.txt`.
4. Genereert een systemd-service (`cybersec-predict.service`) die
   `uvicorn` draait op `0.0.0.0:4444`, met auto-restart bij een crash.
5. Enablet de service (start automatisch bij een reboot) en start hem.
6. Doet een health-check op `/api/health`.

Na afloop: dashboard op `http://<server-ip>:4444/`, API op
`http://<server-ip>:4444/api/...`.

**Beheer:**
```bash
sudo systemctl status cybersec-predict      # status
sudo systemctl restart cybersec-predict     # herstarten (bv. na code-update)
sudo systemctl stop cybersec-predict        # stoppen
sudo journalctl -u cybersec-predict -f      # live logs
sudo ./deploy.sh --uninstall                # service verwijderen
```

**Firewall:** zorg dat poort 4444/tcp open staat, bv. `sudo ufw allow 4444/tcp`.

**Code bijgewerkt?** Draai `sudo ./deploy.sh` gewoon opnieuw — dat
synchroniseert de bestanden, werkt dependencies bij en herstart de service.

## Handmatig starten (development/lokaal testen)

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 4444
```

Open dan `http://localhost:4444/` in je browser — dashboard en API draaien
allebei op diezelfde poort.

Wil je de frontend op een ándere host/poort bereiken dan waar de backend
draait? Zet dit vóór het app-script in `index.html`:

```html
<script>window.SIGNALIS_API_BASE = "http://jouw-adres:4444";</script>
```

## Hoe de voorspelling werkt

1. **Databron per categorie**: de backend probeert eerst live data op te
   halen bij de NVD (National Vulnerability Database) — publicatiedichtheid
   van CVE's die matchen met trefwoorden per categorie (bv. "cloud",
   "kubernetes" voor Cloud Security).
2. **Fallback**: lukt dat niet (geen internet, rate limit, timeout), dan
   valt de server terug op een deterministisch gegenereerde synthetische
   dataset — realistisch gemodelleerd met een basisniveau, groeitrend,
   seizoenscomponent en ruis per categorie.
3. **Voorspelling**: een lichte, dependency-vrije decompositie in
   trend (lineaire regressie) + seizoen (gemiddelde per kalendermaand) +
   ruis (voor de onzekerheidsband). Onzekerheid groeit met `√horizon`,
   zoals gebruikelijk bij random-walk-achtige projecties.
4. **Output**: per categorie krijg je momentum (stijgend/dalend/stabiel),
   een geschat modelvertrouwen, en een forecast met boven-/ondergrens.

## Categorieën die gevolgd worden

- Cloud Security Posture Management
- AI-gedreven detectie & respons
- Zero-Trust Architectuur Tooling
- Identity & Access Management
- Software Supply Chain Security
- IoT / OT Security
- Ransomware-verdediging & Recovery
- Post-Quantum Cryptografie

Wil je een categorie toevoegen of aanpassen? Dat kan in `backend/main.py`,
in de `CATEGORIES`-dictionary (en optioneel `CATEGORY_KEYWORDS` voor de
live NVD-matching).

## Belangrijke kanttekening

Dit model voorspelt **aggregaat, collectief gedrag** — geen individuele
gebeurtenissen, geen garanties. Cybersecurity wordt ook gedreven door
onvoorspelbare schokken (grote breaches, nieuwe wetgeving, geopolitiek).
Gebruik dit voor scenarioverkenning en prioritering, niet als absolute
voorspelling.
