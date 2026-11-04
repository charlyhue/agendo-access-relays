# Fixtures de test

`cle-rsa-de-test.pk8` : clé RSA 2048 bits **jetable**, générée pour les tests du client FCM
(`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER`). Elle ne sert
qu'à signer les assertions OAuth envoyées au faux serveur des tests. Ce n'est pas un secret :
aucun service ne la connaît. Ne jamais la réutiliser ailleurs.
