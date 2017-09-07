package cifradorDAN256;
//Daniel Solis (c) 2017 - Todos los derechos reservados - email jdansolis@gmail.com
//Agosto2017 - Open Source - Open source no is free software!
//Se permite el uso de este programa y algoritmo de forma peronal (individual) sin necesidad del permiso del autor.
//Para cualquier otro uso se requiere permiso por escrito del autor previo pago de licencia de uso (por año o a perpetiudad).

/*
Cifrador de datos a prueba de todo, hasta de ataques cuanticos!
ALGORITMO:

2017- Daniel Solis (c) - email: jdansolis@gmail.com
Este algoritmo de cifrado puede usarse solo bajo licencia de uso en proyectos distribuidos pagando dicha licencia.
para el uso individual (personal) puede ser usado libremente sin permiso del autor
en cada caso incluir datos del credor del algoritmo.

en un mensaje de 579 bytes, por ejemplo:
0 - inicio del proceso
clave: 1 (por ejemplo)

1- calcular sha256 de la clave (pantalla clave):

2-se calculan las posibles posiciones finales, de forma aleatoria, de los bytes semicifrados para crear la sopa
la semilla aleatoria se toma del valor long de 8 bytes tomados de los primeros 8 bytes del hash sha256 de la clave
Tambien podria aplicarse una sopa inicial a cada bloque de acuerdo a la semilla de los ultimos 8 bytes del hash de la clave
para incrementar la dificultad de reconstruccion del mensaje, aunque es a gusto de cada programador que implemente este algoritmo

3-se crea un bloque de 1024 bytes y se escriben 1024 bytes aleatorios (los bytes aleatorios solo para el unico o ultimo bloque del mensaje)
4-se calcula la longitud del mensaje y se escribe en los primeros 4 bytes del bloque dicha longitud en texto plano
si el mensaje es menor a 1021 bytes entonces solo se crea 1 solo bloque para mensajes de longitud menores a 1021 bytes
si el mensaje es mayor a 1024 entonces se crean tantos bloques sean necesarios, solo el ultimo bloque se reserva para 
indicar la longitud del resto del mensaje a cifrar para una recuperacion exitosa
5-se escriben los bytes del mensaje a partir del 5to. byte dentro del bloque (unico o ultimo bloque)
6-cada bloque se segmenta en 32 partes de 32 bytes (256 bits) cada uno para procesarlos

cifrado:
por cada bloque de 1024 bytes, a cifrar, debemos hacer:
n = 0

de cada segmento del bloque (segmento n) se aplica metodo de cerrojos (desplazamiento de bits)
7-desplazamiento (rotacion) de bits a la derecha con reentrada de los bits salientes por la izquierda, 
segun pantalla clave (tomando los 4 bits (nible alto) izquierdos = hasta 16 bits de rotacion) del byte n (1...32)
8-hacer xor con clave (hash sha256)
9-desplazamiento (rotacion) de bits a la derecha con reentrada de los bits salientes por la izquierda,  
segun pantalla clave (tomando los 4 bits derechos (nible bajo)) del byte n (1...32)
10-sumar n++ y repetir el paso 6 hasta terminar el bloque

una vez terminado el proceso anterior por cada bloque que corresponda al mensaje a cifrar se aplicara la sopa de bytes
segun el orden aleatorio obtenido en el paso 2 para completar el cifrado total de cada bloque


decifrar:
Aplicar el proceso a la inversa proporcionando la clave en texto plano (pasos del 0 al 2)

*/

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;

public class CifradoDAN256 {
    private final Random random;
    private final String bitsCero256;
    private long semilla;
    private int[] bytesOrden;
    private String claveBinXor; //contiene los bits para hacer xor
    
    CifradoDAN256() {
        random = new Random();
        bitsCero256 = repiteString( "0", 256 );
    }
    
     public static void main( String[] args ) {
         CifradoDAN256 dan256 = new CifradoDAN256();
         String mensaje = "Hola mundo! Hola mundo! Hola mundo! Hola mundo! Hola mundo!";
         mensaje = dan256.repiteString( "0", 1020 ); 
         String clave = "202.202.202.202";
         
         ArrayList<byte[]> bloques = dan256.cifrar( mensaje.getBytes(), clave );
         ArrayList<byte[]> bloquesDecifrados = dan256.decifrar( bloques.get(0), "101" );

         System.out.println(  );
         System.out.println( "DECIFRADO - DATOS FINALES" );
         byte[] bloqueDecifrado = bloquesDecifrados.get( 0 );
         int c = 0;
         for( int j = 0; j < 32; j++ ) {
             for( int jd = 0; jd < 32; jd++ ) {
                 System.out.print( ((int) bloqueDecifrado[ c ] & 0xff ) + ", " );
                 c++;
             }
             System.out.println(  );
         }
     }
     
     private String repiteString( String string, int nVeces ) {
         String tmp = "";
         for( int j = 0; j < nVeces; j++ ) {
             tmp += string;
         }
         return tmp;
     }
     
     private String SHA256( String string ) {
        try {
            MessageDigest md = MessageDigest.getInstance( "SHA-256" );
            byte[] messageDigest = md.digest( string.getBytes() );
            StringBuffer sb = new StringBuffer();
            
            for ( byte datos : messageDigest ) {
                sb.append( Integer.toString( ( datos &  0xff ) + 0x100, 16 ).substring( 1 ) );
            }
            return  sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return null;
    }
     
     //recibe la totalidad del mensaje raw y la clave raw
     ArrayList<byte[]> cifrar( byte[] mensaje, String clave ) {
         String clavePantalla = SHA256( clave );
         claveBinXor = stringBinario( clavePantalla );
         //estos valores son para todos los bloques a cifrar
         String sSemilla = clavePantalla.substring( 0 , 16 );
         try {
            semilla = Long.valueOf( sSemilla, 16 );
         } catch(Exception e ) { //valor negativo no se acepta como semilla
             semilla = Long.valueOf( "1" + sSemilla.substring( 1 ), 16 );
         }
         calcularPosicionBytesBloque( 1024 );

         System.out.println( "longitud mensaje: " + mensaje.length );
         int nBloques = mensaje.length / 1024;
         
         ArrayList<byte[]> bloques = new ArrayList();
         
         if( nBloques == 0 ) { //el mensaje es menor a 1024 bytes
             byte[] bloque1024 = rellenarRandomBloque();
             if( mensaje.length <= 1020 ) { //1020 + 4 (longitud de mensaje), para formar 1 solo bloque
                 String longitudMensaje = ( "000" + mensaje.length  );
                 longitudMensaje = longitudMensaje.substring( longitudMensaje.length() - 4, longitudMensaje.length() );
                 System.out.println( "longitud mensaje: " +  longitudMensaje );
                 
                 byte[] longitudMensajeB = longitudMensaje.getBytes();
                 bloque1024[ 0 ] = longitudMensajeB[ 0 ]; //escribimos la longitud del mensaje al inicio del mismo
                 bloque1024[ 1 ] = longitudMensajeB[ 1 ];
                 bloque1024[ 2 ] = longitudMensajeB[ 2 ];
                 bloque1024[ 3 ] = longitudMensajeB[ 3 ];
                 for( int j = 0; j < mensaje.length; j++ ) {
                     bloque1024[ j + 4 ] = mensaje[ j ];
                 }

                 System.out.println(  );
                 System.out.println( "DATOS RAW - DATOS INICIALES" );
                 byte[] bloqueDecifrado = bloque1024;
                 int c = 0;
                 for( int j = 0; j < 32; j++ ) {
                     for( int jd = 0; jd < 32; jd++ ) {
                         System.out.print( ((int) bloqueDecifrado[ c ] & 0xff ) + ", " );
                         c++;
                     }
                     System.out.println(  );
                 }
                 byte[] bloqueCifrado = cifrarMensajeBloque( bloque1024, clavePantalla );
                 bloques.add( bloqueCifrado );

             } else { //mensaje no cabe en un solo bloque, necesitamos 2 bloques
                 
             }
         }
         return bloques;
     }
     
     //recibe la totalidad del mensaje cifrado y la clave raw
     ArrayList<byte[]> decifrar( byte[] mensajeCifrado, String clave ) {
         System.out.println(  );
         System.out.println(  );
         System.out.println( "DESCIFRANDO: "  );
         System.out.println(  );
         
         String clavePantalla = SHA256( clave );
         
         claveBinXor = stringBinario( clavePantalla );
         
         //estos valores son para todos los bloques a decifrar
         String sSemilla = clavePantalla.substring( 0 , 16 );
         try {
            semilla = Long.valueOf( sSemilla, 16 );
         } catch(Exception e ) { //valor negativo no se acepta como semilla
             semilla = Long.valueOf( "1" + sSemilla.substring( 1 ), 16 );
         }
         calcularPosicionBytesBloque( 1024 );
         int nBloques = mensajeCifrado.length / 1024;
         ArrayList<byte[]> bloques = new ArrayList();
         if( nBloques == 1 ) {
             byte[] bloquedecifrado = decifrarMensajeBloque( mensajeCifrado, clavePantalla );
             bloques.add( bloquedecifrado );
         }
         
         return bloques;
     }
     
     //rellenar con bytes aleatorios un bloque de 1024 bytes
     private byte[] rellenarRandomBloque() {
         byte[] bloque1024 = new byte[ 1024 ];
         for( int j = 0; j < 1024; j++ ) {
             bloque1024[ j ] = ( byte ) random.nextInt( 256 );
         }
         return bloque1024;
     }
     
     //se utiliza una vez solo para obtener el orden de las posiciones de los bytes cifrados segun semilla obtenida de pantalla clave
     private void calcularPosicionBytesBloque( int tBlock ) {
         Random rnd = new Random( semilla );
         int[] bytes = new int[ tBlock ];
         bytesOrden = new int[ tBlock ];
         
         for( int j = 0; j < tBlock; j++ ) {
             bytes[ j ] = 0;
         }
     
         int nBytes = 0;
         int elByte = 0;
         while( nBytes < tBlock ) {
             elByte = rnd.nextInt( tBlock );
             if( bytes[ elByte ] == 0 ) {
                 bytes[ elByte ] = 1;
                 bytesOrden[ nBytes ] = elByte;
                 nBytes++;
             }
         }
     }

     //recibe un mensaje del tamaño de 1024 bytes (1 bloque) y el resumen sha256 de la clave raw
    private byte[] cifrarMensajeBloque( byte[] mensaje1024, String claveSHA256 ) {
         int nSegmentos = mensaje1024.length / 32;
         
         byte[] nuevoSegmento1024 = new byte[ 1024 ];
         byte[] segmento1024Cifrado = new byte[ 1024 ];
         
         String valorHex = "";
         String valorBin = "";
         int c = 0;
         int c2 = 0;
         for( int j = 0; j < nSegmentos; j++ ) {
             valorHex = "";
             valorBin = "";
             for( int jd = 0; jd < 32; jd++ ) {
                 int enteroByte = (int) mensaje1024[ c ] & 0xff;
                 if( enteroByte < 16 ) {
                     valorHex += "0";
                 }
                 valorHex += Integer.toHexString(enteroByte);
                 c++;
             }

             int rotacionR = Integer.valueOf( claveSHA256.substring( c2, c2+1 ), 16 );
             valorBin = stringBinario( valorHex );
             valorBin = rotacionBitsR( valorBin, rotacionR );
             valorBin = segmentoXor( valorBin );
             rotacionR = Integer.valueOf( claveSHA256.substring( c2+1, c2+2 ), 16 );
             c2 += 2;

             valorBin = rotacionBitsR( valorBin, rotacionR );
             
             //escribimos el segmento semicifrado
             byte[] segmentoSemi = stringBinarioByte( valorBin );
             int pos = j * 32;
             for( int jd = 0; jd < 32; jd++ ) {
                 nuevoSegmento1024[ pos + jd ] = segmentoSemi[ jd ];
             }
         }
         
         //reubicar bytes del block segun orden obtenido por la semilla proporcionada por la pantalla clave
         for( int j = 0; j < 1024; j++ ) {
             segmento1024Cifrado[ j ] = nuevoSegmento1024[ bytesOrden[ j ] ];
         }
         
         System.out.println(  );
         System.out.println( "DATOS CIFRADOS - DATOS PROCESADOS" );
         byte[] bloqueDecifrado = segmento1024Cifrado;
         int cc = 0;
         for( int j = 0; j < 32; j++ ) {
             for( int jd = 0; jd < 32; jd++ ) {
                 System.out.print( ((int) bloqueDecifrado[ cc ] & 0xff ) + ", " );
                 cc++;
             }
             System.out.println(  );
         }
         return segmento1024Cifrado;
    }
    
    //recibe un mensaje cifrado del tamaño de 1024 bytes (1 bloque) y el resumen sha256 de la clave raw
    private byte[] decifrarMensajeBloque( byte[] mensaje1024, String claveSHA256 ) {
         int nSegmentos = mensaje1024.length / 32;
         
         byte[] nuevoSegmento1024 = new byte[ 1024 ];
         byte[] segmento1024decifrado = new byte[ 1024 ];
         
         for( int j = 0; j < 1024; j++ ) {
             nuevoSegmento1024[ bytesOrden[ j ] ] = mensaje1024[ j ];
         }
         
         String valorHex = "";
         String valorBin = "";
         int c = 0;
         int c2 = 0;
         for( int j = 0; j < nSegmentos; j++ ) {
             valorHex = "";
             for( int jd = 0; jd < 32; jd++ ) {
                 int enteroByte = (int) nuevoSegmento1024[ c ] & 0xff;
                 if( enteroByte < 16 ) {
                     valorHex += "0";
                 }
                 valorHex += Integer.toHexString(enteroByte);
                 c++;
             }
             
             valorBin = stringBinario( valorHex );
             int rotacionL = Integer.valueOf( claveSHA256.substring( c2+1, c2+2 ), 16 );
             valorBin = rotacionBitsL( valorBin, rotacionL );
             valorBin = segmentoXor( valorBin );
             rotacionL = Integer.valueOf( claveSHA256.substring( c2, c2+1 ), 16 );
             valorBin = rotacionBitsL( valorBin, rotacionL );
             c2 += 2;
             
             //escribimos el segmento decifrado
             byte[] segmentoSemi = stringBinarioByte( valorBin );
             int pos = j * 32;
             for( int jd = 0; jd < 32; jd++ ) {
                 segmento1024decifrado[ pos + jd ] = segmentoSemi[ jd ];
                 //System.out.print( ((int) segmentoSemi[ jd ] & 0xff ) + ", " );
             }
         }
         return segmento1024decifrado;
    }
    
    //convierte un string binario a un array de 32 bytes
    private byte[] stringBinarioByte( String stringBinario ) {
        byte[] bytes = new byte[ 32 ];
        int pos = 0;
        for( int j = 0; j < 32; j++ ) {
            pos = j << 3; // * 8;
            bytes[ j ] = (byte) Integer.parseInt( stringBinario.substring( pos, pos + 8 ), 2 );
        }
        return bytes;
    }
    
    //permite hacer xor a 2 segmentos string de 256 bits cada uno
    private String segmentoXor( String segmento ) {
        String xor = "";
        for( int j = 0; j < claveBinXor.length(); j++ ) {
            if( claveBinXor.substring( j, j + 1 ).startsWith( segmento.substring( j, j+1 ) ) ) {
                xor += "0"; // 1 xor 1 - 0 xor 0 = 0
            } else {
                xor += "1"; // 1 xor 0 - 0 xor 1 = 1
            }
        }
        return xor;
    }

    //Rotacion de bits a la derecha con reemtrada por la izquierda
    String rotacionBitsR( String stringBinario, int nBits ) {
        if( nBits == 0 ) return stringBinario;
        
        String rotacion = stringBinario.substring( stringBinario.length() - (nBits++) , stringBinario.length() );
        nBits--;
        
        int lenStringBinario = 256 - stringBinario.length();
        String bitsFaltantes = "";
        if( lenStringBinario > 0 ) {
            bitsFaltantes = bitsCero256.substring( 0, lenStringBinario );
        }
        stringBinario = rotacion + bitsFaltantes + stringBinario.substring( 0, stringBinario.length() - nBits );
        return stringBinario;
    }
    
    //rotacion de bits a la izquierda con reentrada por la derecha
    String rotacionBitsL( String stringBinario, int nBits ) {
        if( nBits == 0 ) return stringBinario;

        int lenStringBinario = 256 - stringBinario.length();
        String bitsFaltantes = "";
        if( lenStringBinario > 0 ) {
            bitsFaltantes = bitsCero256.substring( 0, lenStringBinario );
        }
        stringBinario =  bitsFaltantes + stringBinario;
        String rotacion = stringBinario.substring( 0, nBits );
        stringBinario = stringBinario.substring( nBits, stringBinario.length() ) + rotacion;
        return stringBinario;
    }
    
    //recibe un string hexadecimal de 64 nibles o 32 bytes
    private String stringBinario( String stringHex ) {
        String binario = "";
        String c = "";
        for( int j = 0; j < stringHex.length(); j++ ) {
            c = stringHex.substring( j, j+1 );
            switch( c ) {
                case "0":
                    binario += "0000";
                    break;
                case "1":
                    binario += "0001";
                    break;
                case "2":
                    binario += "0010";
                    break;
                case "3":
                    binario += "0011";
                    break;
                case "4":
                    binario += "0100";
                    break;
                case "5":
                    binario += "0101";
                    break;
                case "6":
                    binario += "0110";
                    break;
                case "7":
                    binario += "0111";
                    break;
                case "8":
                    binario += "1000";
                    break;
                case "9":
                    binario += "1001";
                    break;
                case "A":
                case "a":
                    binario += "1010";
                    break;
                case "B":
                case "b":
                    binario += "1011";
                    break;
                case "C":
                case "c":
                    binario += "1100";
                    break;
                case "D":
                case "d":
                    binario += "1101";
                    break;
                case "E":
                case "e":
                    binario += "1110";
                    break;
                case "F":
                case "f":
                    binario += "1111";
            }
        }
        return binario;
    }
}
