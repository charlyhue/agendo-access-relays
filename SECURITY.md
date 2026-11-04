# Signaler une vulnérabilité

Merci de ne pas ouvrir de ticket public pour une faille de sécurité. Utilisez le signalement
privé de GitHub (onglet **Security**, puis **Report a vulnerability**) sur ce dépôt.

Indiquez la version (commit ou étiquette d'image), le composant (`relay-sni` ou `relay-push`),
les étapes pour reproduire et l'effet constaté. Nous accusons réception sous quelques jours.

Le modèle de menace d'Agendo Access est décrit dans la spécification du socle (section
« Sécurité »). En résumé, un relais SNI compromis ne doit pouvoir ni lire le trafic, ni usurper
une maison, ni fabriquer un jeton. Un relais push compromis ne doit pouvoir ni lire ni fabriquer
une notification lisible.
