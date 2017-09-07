# cifradorDAN256
Cifrador de datos no convencional muy resistente a cualquier ataque conocido y contra ataques de computación cuántica!.

Hola amigos, ¿Cansados de usar cifradores de datos con librerias externas?
El cifrador de datos CifradorDAN256 no requiere ni una sola libreria externa para funcionar. La implementacion en este caso es de una clave
de 256 bits obtenida de hacer hash sha256 a la clave escrita en texto plano. De ahi en adelante todo el proceso de cifrado corresponde
integramente de la clave proporcionada... no existen extensas tablas de numeros para cifrar sino simplemente LA CLAVE del usuario la cual
puede ser desde una letra de longitud hasta un extenso poema de amor (o de lo que sea jejeje) pues al obtener el hash256 de dicha clave obtendremos
la firma digital correspondiente de un tamaño de 256 bits!.

Un mensaje de longitud menor a 1024 bytes introduce ruido en forma de bytes aleatorios para despistar al enemigo jejeje, por lo tanto,
si repitieras un mensaje 100000000000000000000000000000... de veces (por ejemplo, un mensaje de: "Hola Mundo! soy Daniel Solis.") de longitud 29 bytes + 4 bytes
de señalizacion serian 33 bytes en un bloque de 1024 bytes aleatorios, bytes totalmente arbitrarios cada vez, el bloque cifrado seria tan
distinto siempre de los demas y ninguno siquiera se aproximaria a algo parecido entre ellos.

La otra cara de la moneda, que para lograr decifrar un mensaje sin la clave seria tan dificil como la imposibilidad matematica de que existan 2
planetas tierra con las mismas variables del nuestro. Esto se debe que en la parte final del cifrado los bytes se reubican dentro del bloque
de forma aleatoria, cuya semilla se encuentra solo en la CLAVE del usuario, ¿Imaginas intentar ordenar de forma correcta 256^1024 posibilidades?
sin la posibilidad de conocer la CLAVE hash porque para cada posible combinacion se tendria que probar a ver si se obtiene algun mensaje 
en claro, lo que incrementa la dificultad a 256^1024^256 y bingo!

Bueno, si les gusta el programa y el algoritmo y desean apoyarme para comprar mis refrescos siempre podran enviarme algo de BitCoins BTC
a la siguiente direccion BTC: 1KoehXydWrKm6b9gEo6wXuHEX1Vu6Sqjju (cualquier cantidad de satoshis son buenos).

(el universo y yo se lo agradeceremos enormemente!)
