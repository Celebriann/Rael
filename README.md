<html>

  <body>
    <h4>Pour l'instant seul linux a été testé</h4>
    <h1>DESCRIPTION</h1>
    <p>Un petit chat chiffré, il y a un historique de message dans les channels (à partir de la V1.3), celui si est stocké sur la machine du créateur. </br>Les mp ne sont pas enregistrés</p>
    <h1>INSTALLATION</h1>
    <p>Installer Tor</p>
    <p>Installer python3</p>
    <h2>LINUX</h2>
    <ul>
      <li><h3>Serveur</h3>
        <ul>
          <li>cryptography</li>
          <li>argon2-cffi</li>
        </ul>
      </li>
      <li>
        <h3>Client</h3>
        <ul>
          <li>cryptography</li>
          <li>pysocks</li>
          <li>argon2-cffi</li>
          <li>textual</li>
        </ul>
      </li>
    </ul>
    <h1>INSTRUCTIONS</h1>
    <p>Lors du premier lancement du serveur cela va générer un fichier "server.crt", ce fichier doit aussi être présent à côté des clients</p>
    <p>Les données de votre profil sont stockés dans un dossier "user.json" sur la machine cliente</p>
  </body>
</html>
