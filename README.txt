Intro
-----

Ce produit vise � impl�menter une politique de s�curit� plus forte que
celle par d�faut:

- D�sactivation du rappel de mot de passe
- D�sactivation du cookie conservant le login
- Directories pas lisibles pour les anonymes
- Contraintes sur les mots de passe
- D�sactivation des comptes apr�s 3 �checs de connexion
- Obligation de changer les MDP 

Etaient d�ja impl�ment�s dans CPS 3.2.3:

- Le nom et le mail des auteurs de documents ne sont pas montr�s aux anonymes.


Pr�requis
---------

Zope 2.7.3 + CPS 3.2.4 + toutes les d�pendances.

CMFQuickInstaller peut aider (cf. infra).

Installation
------------

1. Installer le produit

2. Instancier un site CPS

3. Instancier un objet de type "CPS Security Policy Tool" depuis la ZMI

4. Choisir le mode de s�curit� depuis la ZMI

Principe
--------

L'installation du produit d�clenche:

- La surcharges de quelques templates et scripts dans la skin security_policy
- Des modifications sur les widgets "Password".

