# LEARN.md : comprendre phishing-analyzer (guide pour Mohamed)

Ce document explique **chaque détection** de l'outil, avec le *pourquoi* côté attaquant et
côté défenseur. Il te prépare aussi aux questions d'entretien (SOC analyst, stage PFE). Lis-le
avec le code ouvert à côté : chaque section indique le fichier concerné.

---

## 1. Le contexte : le triage de phishing dans un SOC

Le phishing reste le premier vecteur d'accès initial : technique **T1566** de MITRE ATT&CK,
avec les sous-techniques `.001` (pièce jointe), `.002` (lien) et `.003` (via un service tiers).
Dans un SOC, l'analyste N1 reçoit les e-mails signalés par les utilisateurs et doit
rapidement répondre à trois questions :

1. Est-ce malveillant ? (verdict)
2. Qu'est-ce qui le prouve ? (preuves / *findings*)
3. Que faut-il bloquer ou chercher ailleurs ? (IOC : domaines, URLs, IP, hashes)

L'outil automatise ces trois réponses **sans jamais exécuter ni ouvrir** le contenu
dangereux. Le verdict final reste celui de l'analyste.

---

## 2. Parsing d'un .eml (`parser.py`)

Un `.eml` est un message au format RFC 5322, avec des en-têtes puis un corps. Le corps est
structuré en MIME (`multipart/mixed`, `multipart/alternative`...). On utilise le module
standard `email` avec `policy.default`, qui décode les *encoded-words*
(`=?utf-8?q?...?=`) et les noms de fichiers RFC 2231.

**Piège découvert pendant le développement :** pour l'en-tête
`From: support@microsoft.com <helpdesk@evil.test>` (un `@` non quoté dans le nom affiché),
l'objet d'en-tête structuré de Python renvoie seulement `support@microsoft.com`. Il
**perd la vraie adresse**. Un outil naïf conclurait donc que le mail vient de Microsoft.
C'est pourquoi les en-têtes d'adresse sont relus depuis leur valeur brute, en privilégiant
l'adresse entre `< >`, celle où partent réellement les réponses. Un test de non-régression
couvre ce cas (`test_parser.py`).

---

## 3. Authentification e-mail (`auth.py`, `dns_check.py`)

### SPF (Sender Policy Framework, RFC 7208)
- **Principe :** le domaine publie dans un enregistrement DNS TXT `v=spf1 ...` la liste des serveurs (IP) autorisés à envoyer pour lui.
- **Ce qui est vérifié :** le domaine de l'**enveloppe** (`MAIL FROM`, visible dans `Return-Path`), **pas** le `From:` affiché à l'utilisateur.
- **Résultats possibles :** `pass`, `fail` (`-all`, rejet strict), `softfail` (`~all`, « probablement pas autorisé »), `neutral`, `none`, `permerror`, `temperror`.
- **Limite :** un attaquant peut passer SPF avec son propre domaine, tout en affichant un autre domaine dans `From:`.

### DKIM (DomainKeys Identified Mail, RFC 6376)
- **Principe :** le serveur d'envoi signe certains en-têtes et le corps avec une clé privée. La clé publique est publiée en DNS, sous `selector._domainkey.domaine`.
- **Ce que prouve un `pass` :** le message n'a pas été modifié et il a été signé par le domaine `d=`.
- **Limite :** `d=` peut être n'importe quel domaine, pas forcément celui du `From:`.

### DMARC (RFC 7489)
- **Principe :** DMARC relie SPF et DKIM au `From:` visible grâce à l'**alignement**. DMARC réussit si SPF ou DKIM réussit **et** si leur domaine correspond au domaine du `From:`. Par défaut l'alignement est *relâché* (`aspf=r`/`adkim=r` : même domaine organisationnel, `mail.exemple.com` s'aligne avec `exemple.com`) ; en mode *strict* (`aspf=s`/`adkim=s`) il faut le domaine exact.
- **Politiques :** le propriétaire du domaine publie `p=none` (surveillance), `p=quarantine` (spam) ou `p=reject` (rejet), dans `_dmarc.domaine`.
- **Lecture :** un `dmarc=fail` signifie que le `From:` est très probablement usurpé (poids 30 dans l'outil).

### Authentication-Results et le modèle de confiance
Le serveur de réception écrit le résultat dans l'en-tête `Authentication-Results`
(RFC 8601). **Mais n'importe qui peut écrire cet en-tête dans son mail !** Les nouveaux
en-têtes sont ajoutés **en haut**. L'outil ne fait donc confiance qu'à l'en-tête **le plus
haut**, celui que ta passerelle a ajouté en dernier, ou à celui dont l'`authserv-id`
correspond à `--authserv-id`. L'échantillon 06 contient un faux en-tête `dmarc=pass` plus
bas : il est ignoré.

**Nuance importante (question piège d'entretien) :** la règle « le plus haut » n'est sûre
que si ta passerelle ajoute **réellement** un `Authentication-Results` à chaque message. Si
elle n'en ajoute pas, le plus haut peut être celui de l'attaquant. En production, on passe
donc toujours `--authserv-id`, et la RFC 8601 (section 5) demande à la passerelle de
supprimer les en-têtes entrants qui portent déjà son propre identifiant. Microsoft 365 écrit
son en-tête sans authserv-id (`Authentication-Results: spf=pass ...`) : dans ce cas, c'est la
règle « le plus haut » qui s'applique.

**Point clé d'entretien :** « SPF/DKIM/DMARC = pass » **ne veut pas dire** « légitime ».
L'échantillon 03 passe les trois contrôles, parce que l'attaquant possède le domaine sosie
`attijariwafabnak.test`, et il reste du phishing.

### Mode `--online`
Ce mode interroge le DNS public pour les enregistrements TXT SPF et DMARC du domaine
expéditeur. On réutilise l'approche du projet `rssi-audit` : trouver `v=spf1`, lire le
qualificateur `all`, trouver `v=DMARC1` et lire `p=`. Un domaine en NXDOMAIN (inexistant)
est suspect : c'est un domaine jetable ou déjà supprimé.

---

## 4. Anomalies d'en-têtes (`headers.py`)

| Contrôle | Pourquoi c'est suspect |
|---|---|
| **Reply-To ≠ From** | La victime croit répondre au PDG ou à la banque, mais sa réponse part chez l'attaquant. C'est typique de la fraude au président (BEC). |
| **Return-Path ≠ From** | C'est l'adresse de rebond (enveloppe). C'est **normal** pour les newsletters envoyées par un ESP (Mailchimp, Sendgrid...), d'où son poids faible (5). Cela devient significatif avec un SPF ou un DMARC en échec. |
| **Nom affiché contenant une autre adresse** | Exemple : `"support@microsoft.com" <helpdesk@m365-alerts.test>`. Sur mobile, seul le nom s'affiche. Techniques T1684.002 (Email Spoofing) et T1684.001 (Impersonation). |
| **Nom affiché = marque, domaine non officiel** | « PayPal Service » envoyé depuis `paypa1.test`, ou « Microsoft Security » depuis une adresse `@outlook.com` : `outlook.com`/`gmail.com` appartiennent bien à Microsoft/Google, mais n'importe qui peut y ouvrir une boîte. L'IOC retenu est alors l'adresse, jamais le fournisseur (on ne bloque pas `gmail.com`). |
| **Titre de dirigeant + domaine externe** | « Karim - PDG » qui écrit depuis un domaine différent de celui du destinataire : un vrai PDG écrit depuis le domaine de l'entreprise. |
| **Message-ID d'un autre domaine** | Signal faible : beaucoup de services tiers font pareil. |

### La chaîne `Received`
Chaque serveur SMTP qui relaie le message **ajoute en haut** une ligne
`Received: from X [IP] by Y; date`. Pour reconstituer le trajet, on lit donc **de bas en
haut** : le premier saut est en bas. L'outil :
- liste les sauts du plus ancien au plus récent, avec l'IP et le délai entre deux sauts ;
- signale les horodatages qui « remontent le temps » (plus de 5 minutes), qui peuvent trahir des en-têtes forgés ou une simple dérive d'horloge (poids faible) ;
- signale un en-tête `Date:` incohérent avec le premier saut ;
- extrait l'IP du premier relais externe comme IOC.

**Attention :** seuls les en-têtes `Received` ajoutés par **tes** serveurs sont fiables.
Tout ce qui est en dessous peut avoir été inventé par l'expéditeur.

---

## 5. Domaines sosies (`lookalike.py`)

C'est la technique T1583.001 (Acquire Infrastructure: Domains) : l'attaquant enregistre
un domaine qui ressemble à la marque.

1. **Homoglyphes :** des caractères visuellement identiques. Exemples : `а` cyrillique (U+0430) et `a` latin, `0`/`o`, `1`/`l`, `rn`/`m`. L'outil calcule un « squelette » (*skeleton*) en remplaçant chaque caractère par son sosie latin. Si le squelette d'un morceau du domaine est égal à la marque alors que le texte brut est différent, c'est un homoglyphe.
2. **Punycode (IDN) :** les domaines Unicode sont encodés en ASCII avec le préfixe `xn--`. Par exemple, `xn--attijariwafabnk-6lm.test` s'affiche `attijariwafabаnk.test` avec un `а` cyrillique. L'outil décode le domaine et vérifie s'il **mélange plusieurs écritures** (latin + cyrillique) : c'est l'attaque homographe classique.
3. **Typosquatting :** on mesure la **distance de Damerau-Levenshtein** (variante *optimal string alignment*) : le nombre minimal d'insertions, suppressions, substitutions ou **inversions de deux lettres voisines**. `attijariwafabnak` est à 1 inversion de `attijariwafabank`. Les seuils sont ≤1 pour les mots-clés de 6 caractères ou plus et ≤2 pour ceux de 9 ou plus. On exige aussi la même première lettre, pour éviter les faux positifs comme `cloud` et `icloud`.
4. **Marque incluse dans le domaine :** `paypal.com.secure-login.test` ou `cihbank-securite.test`. Les marques courtes (`dhl`, `cih`) ne sont comparées qu'à des morceaux entiers du domaine, pour éviter que `adhlong` déclenche `dhl`.

Un domaine officiel, ou un sous-domaine d'un domaine officiel (`www.paypal.com`), n'est
**jamais** signalé. La liste se trouve dans `data/brands.json` : banques marocaines
(Attijariwafa, Bank of Africa, CIH, Banque Populaire, BMCI, Crédit du Maroc, Saham Bank ex-SG Maroc,
Crédit Agricole du Maroc, Al Barid Bank),
opérateurs, DGI, CNSS, et grandes marques. **Il faut la vérifier et l'adapter** à
l'organisation que tu protèges.

---

## 6. Liens (`urls.py`)

Les URLs sont extraites du texte brut et du HTML (`<a href>`, `<form action>`, `src`, texte
visible), avec `html.parser`. Le HTML n'est **jamais rendu** et aucune URL n'est visitée.

| Ruse | Explication |
|---|---|
| **IP brute** `http://192.0.2.45/login` | Évite la réputation de domaine ; c'est typique des kits hébergés sur des serveurs compromis. |
| **IP obfusquée** `http://3232235777/` | La même IP écrite en décimal ou en hexadécimal. |
| **`@` dans l'URL** `https://www.paypal.com@198.51.100.7/` | Tout ce qui est avant `@` est un *nom d'utilisateur* ; le navigateur va réellement sur `198.51.100.7`. |
| **Texte ≠ cible** | Le lien affiche `https://www.paypal.com/signin` alors que le href pointe ailleurs. C'est le cœur du phishing par lien. |
| **Formulaire dans le mail** | Il peut envoyer le mot de passe directement à l'attaquant (T1598.003). |
| **`javascript:` / `data:`** | Exécute du code ou affiche une page embarquée (HTML smuggling, T1027.006). |
| **Raccourcisseurs, TLD abusés** | Ils masquent la destination ou indiquent une infrastructure bon marché. Ce sont des signaux faibles. |

Les URLs sont **« défangées »** dans les rapports (`hxxps://evil[.]test`) pour qu'aucun clic
accidentel ne soit possible dans le ticket.

---

## 7. Pièces jointes (`attachments.py`) : analyse statique uniquement

On calcule le **SHA-256** (et le MD5, utile pour certaines bases de threat intel), la
taille et le type MIME. Ensuite :

- **Double extension** `Facture.pdf.exe` : Windows masque les extensions connues, donc l'utilisateur voit `Facture.pdf` (T1036.007).
- **RTLO (U+202E)** : ce caractère inverse l'affichage, si bien que `facture[U+202E]fdp.exe` s'affiche `facture` + `exe.pdf` (T1036.002).
- **Exécutables et scripts** : exe, js, vbs, hta, lnk, ps1, one... (T1204.002, l'utilisateur exécute le fichier).
- **Macros Office** : extensions `.docm`/`.xlsm`, ou présence de `vbaProject.bin` dans le ZIP OOXML, détectée en lisant **seulement la liste** des fichiers de l'archive (T1059.005, VBA).
- **ISO/IMG/VHD** : historiquement, ces conteneurs contournaient le *Mark-of-the-Web* (T1553.005).
- **HTML/SVG joint** : page de phishing locale ou HTML smuggling.
- **ZIP chiffré** : l'antivirus de la passerelle ne peut pas l'analyser.
- **Magic bytes** : un fichier `.jpg` qui commence par `MZ` est en réalité un exécutable Windows.

Pour aller plus loin, toujours dans une **sandbox** : `olevba` (oletools), `pdfid`, ou une
détonation dans Cuckoo/CAPE.

---

## 8. Ingénierie sociale (`keywords.py`)

Le texte est normalisé (minuscules, accents supprimés) puis comparé à des expressions en
français et en anglais, réparties en catégories :
- **urgence** : « sous 24h », « immédiatement », *within 24 hours* ;
- **menace** : « compte suspendu », *unusual activity* ;
- **identifiants** : « mot de passe », « vérifiez votre compte », « code OTP » ;
- **paiement** : « virement », « RIB », « IBAN », « nouveau RIB », « cartes cadeaux » ;
- **secret / isolement** : « confidentiel », « je suis en réunion », « n'en parle à personne ».

La règle composite **`bec_pattern`** se déclenche avec paiement + (urgence ou secret), **sans
lien ni pièce jointe**. Une fraude au président ne contient aucune charge malveillante :
l'attaque, c'est la conversation. Les scanners d'URL et d'antivirus ne voient donc rien.

---

## 9. Score et verdict (`scoring.py`)

- Chaque *finding* a un poids. Chaque identifiant compte **une seule fois**, avec son poids maximal.
- Le score est la somme des poids, plafonnée à 100.
- Moins de 25 donne *Likely safe*, de 25 à 59 *Suspicious*, 60 et plus *Likely phishing*. Un *finding* `critical` donne au minimum *Suspicious*.
- **Honnêteté :** les poids ont été choisis à la main et testés sur des échantillons synthétiques, **pas** calibrés sur un vrai corpus. Pour améliorer l'outil, il faudrait mesurer précision et rappel sur un jeu de données étiqueté (par exemple les signalements réels d'une entreprise, anonymisés).

---

## 10. 15 questions d'entretien et réponses modèles

**1. Quelle est la différence entre SPF, DKIM et DMARC ?**
SPF autorise des IP d'envoi pour le domaine de l'enveloppe (MAIL FROM). DKIM signe
cryptographiquement le message au nom d'un domaine `d=`. DMARC exige qu'au moins l'un des
deux réussisse **et** soit aligné avec le domaine du `From:` visible. DMARC définit aussi une
politique (none/quarantine/reject) et des rapports (`rua`).

**2. Un e-mail passe SPF, DKIM et DMARC. Est-il sûr ?**
Non. Cela prouve seulement que le propriétaire du domaine l'a envoyé. Un attaquant qui
enregistre `attijariwafabnak.com` configure SPF/DKIM/DMARC et passe les trois contrôles. Il
faut regarder le domaine lui-même, les liens et le contenu. Un compte légitime compromis
passe aussi.

**3. Comment lire une chaîne `Received` ?**
De bas en haut : chaque serveur ajoute sa ligne en haut. Le premier saut externe donne
l'IP d'origine probable. Seuls les en-têtes ajoutés par nos propres serveurs sont fiables ;
les lignes du bas peuvent être forgées. On vérifie aussi la cohérence des horodatages.

**4. Pourquoi ne pas faire confiance à tous les en-têtes `Authentication-Results` ?**
Parce que l'expéditeur peut en insérer un faux (`dmarc=pass`). On ne fait confiance qu'à
celui ajouté par notre passerelle (le plus haut, ou celui avec notre `authserv-id`), et
idéalement la passerelle supprime les en-têtes entrants qui portent son identifiant.

**5. Qu'est-ce qu'une attaque homographe ?**
L'utilisation de caractères Unicode visuellement identiques (cyrillique `а`, grec `ο`) pour
créer un domaine qui ressemble à une marque. Il est encodé en punycode `xn--...`. Les
navigateurs modernes affichent le punycode quand les écritures sont mélangées, mais les
clients mail et les SMS ne le font pas toujours.

**6. Que signifie « défanger » un IOC et pourquoi ?**
Rendre une URL ou un domaine non cliquable (`hxxps://evil[.]com`) pour éviter un clic ou
une résolution automatique accidentelle dans un ticket, un chat ou un e-mail interne.

**7. Qu'est-ce qu'une fraude au président (BEC), et pourquoi est-elle difficile à détecter ?**
Un attaquant se fait passer pour un dirigeant ou un fournisseur et demande un virement ou un
changement de RIB. Il n'y a ni lien ni pièce jointe, donc rien à scanner. La détection
repose sur le contexte : Reply-To divergent, domaine externe, urgence et secret. La vraie
parade est la vérification hors bande (rappeler sur un numéro connu) et une procédure de
double validation des virements.

**8. Pourquoi `Facture.pdf.exe` est-il dangereux ?**
Windows masque par défaut les extensions connues : l'utilisateur voit `Facture.pdf` alors
que c'est un exécutable. C'est la technique ATT&CK T1036.007 (Double File Extension).

**9. Comment analyser une pièce jointe suspecte sans risque ?**
Ne jamais l'ouvrir sur un poste de travail. Calculer son hash et le chercher en threat
intel. Faire une analyse statique (magic bytes, `olevba` pour les macros, `pdfid`), puis si
besoin une détonation dans une sandbox isolée. Mon outil ne fait que l'étape statique.

**10. Quelles techniques MITRE ATT&CK associes-tu au phishing ?**
T1566.001 (pièce jointe), T1566.002 (lien), T1566.003 (via un service : LinkedIn, Teams,
WhatsApp...), T1598.003 (phishing pour voler des informations), T1534 (Internal
Spearphishing, depuis une boîte interne compromise), T1684.001 (Impersonation) et
T1684.002 (Email Spoofing), T1036.007 (double extension), T1204.001/.002 (exécution par
l'utilisateur), et T1583.001 (achat de domaines) côté préparation. À savoir : ATT&CK v19
(avril 2026) a révoqué T1656 *Impersonation* et T1672 *Email Spoofing* et les a déplacées
sous T1684 *Social Engineering* ; beaucoup de règles SIEM utilisent encore les anciens ids.

**11. Quelle différence entre `~all` et `-all` dans SPF ?**
`-all` (fail) demande de rejeter les serveurs non listés. `~all` (softfail) demande
seulement de les marquer comme suspects ; beaucoup de messages passent quand même. `+all`
autorise tout le monde, ce qui rend SPF inutile.

**12. Comment réduis-tu les faux positifs de ton outil ?**
Poids faible pour les signaux ambigus (Return-Path des ESP, Message-ID). Chaque règle compte
une seule fois. Les domaines officiels et leurs sous-domaines sont exclus. Les marques
courtes ne sont comparées qu'à des morceaux entiers du domaine, et le typosquatting exige la
même première lettre. Enfin, chaque alerte est expliquée, pour que l'analyste puisse la
juger. Pour aller plus loin, il faudrait mesurer sur un corpus réel.

**13. Quelles sont les limites d'une détection par mots-clés ?**
Elle est facile à contourner (images, caractères invisibles, fautes volontaires, autres
langues comme l'arabe ou la darija) et génère des faux positifs (un vrai mail de
réinitialisation de mot de passe). C'est un signal parmi d'autres, jamais un verdict seul.

**14. Après avoir confirmé un phishing, que fait l'analyste ?**
Bloquer l'expéditeur, le domaine et les URLs (passerelle mail, proxy, DNS). Rechercher les
autres destinataires dans les logs et purger leurs boîtes. Vérifier qui a cliqué ou saisi
des identifiants (logs proxy et IdP), réinitialiser les mots de passe et révoquer les
sessions. Partager les IOC, documenter le ticket et répondre à l'utilisateur qui a signalé.

**15. Pourquoi ton rapport HTML n'affiche-t-il pas le HTML du mail ?**
Parce que rendre le HTML malveillant pourrait charger des ressources distantes (pixels de
suivi qui confirment la lecture), exécuter des scripts ou tromper l'analyste. Le rapport
échappe toutes les valeurs, n'a aucune dépendance externe, déclare une
Content-Security-Policy stricte et affiche les URLs défangées.

---

## 11. Ligne de CV (honnête)

> **phishing-analyzer** (projet personnel, Python) : outil CLI de triage SOC N1 qui analyse
> un e-mail suspect (.eml) : SPF/DKIM/DMARC, chaîne Received, domaines sosies
> (homoglyphes/punycode/typosquatting), liens, pièces jointes en statique, leviers FR/EN. Il
> produit un score de risque expliqué et relié à MITRE ATT&CK, un rapport JSON/HTML et des IOC
> défangés. 93 tests pytest ; validé sur des échantillons synthétiques.

(Ne prétends pas qu'il a été utilisé en production ni validé sur des mails réels : ce n'est pas le cas.)
