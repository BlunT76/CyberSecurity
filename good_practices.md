# Bonnes pratiques en vrac

## GitHub
- Attention à ce que l'on push sur GitHub ! Password , infos de connection à une DB , .env . 
- Si des infos sensibles ont été push, il est plus prudent de supprimer entièrement le repo (car tout est visible dans les commits) et de changer , autant que possible , les données sensibles

## Heroku 
- Il est possible de définir des variables d'environnement, soit via une interface graphique sur la plateforme Heroku , soit en ligne de commande. Celles ci sont par exemple les données de connection à une DB , pour éviter d'envoyer en plaintext ces infos.
##### Command line
```
$ heroku config
// pour afficher toutes les variables de config
```
```
$ heroku config:set DB_NAME=papaly
// pour créer une variable de config
```
##### Dashboard Heroku de votre App => Settings => Config vars
![Heroku config vars](http://image.noelshack.com/fichiers/2018/44/2/1540890498-configvars.png)

