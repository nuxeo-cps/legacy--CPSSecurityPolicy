Intro
-----

Ce produit vise à implémenter une politique de sécurité plus forte que
celle par défaut:

- Désactivation du rappel de mot de passe
- Désactivation du cookie conservant le login
- Directories pas lisibles pour les anonymes
- Contraintes sur les mots de passe
- Désactivation des comptes après 3 échecs de connexion
- Obligation de changer les MDP 

Etaient déja implémentés dans CPS 3.2.3:

- Le nom et le mail des auteurs de documents ne sont pas montrés aux anonymes.


Prérequis
---------

Zope 2.7.3 + CPS 3.2.4 + toutes les dépendances.

CMFQuickInstaller peut aider (cf. infra).

Installation
------------

1. Installer le produit

2. Instancier un site CPS

3. Instancier un objet de type "CPS Security Policy Tool" depuis la ZMI

4. Choisir le mode de sécurité depuis la ZMI

Principe
--------

L'installation du produit déclenche:

- La surcharges de quelques templates et scripts dans la skin security_policy
- Des modifications sur les widgets "Password".

