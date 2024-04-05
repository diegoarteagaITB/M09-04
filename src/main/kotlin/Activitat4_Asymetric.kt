import java.io.File
import java.io.FileInputStream
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator


fun main(args: Array<String>) {
    var opcio: Int
    var kstore: KeyStore
    var pubKey: PublicKey
    var priKey: PrivateKey? = null
    var encriptat: ByteArray?
    var decript: ByteArray?
    var btext: ByteArray? = null
    var text: String
    var ubicacioKS: String
    var passKS: String
    var alias: String

    //En bucle fins que no decidim sortir
    do {
        opcio = demanarMode()

        if (opcio == 1) {
            //Demanem el text
            //Calculem el tamany en bytes i controlem que no sigui major que 245. Si és major, tornem a demanar
            do {
                text = demanarText()
                if (text.length > 245) {
                    println("El text té un tamany de " + text.length + " bytes, és superior a 245 bytes")
                }
            } while (text.length > 245)

            //XIFRAR
            //Demanem la ubicació i el password de la keystore
            btext = text.toByteArray()
            val magatzem:Boolean = demanarMagatzemClaus()
            if (magatzem == true) {
                //System.out.print("Dona'm l'ubicació del magatzem de claus: ");
                //ubicacioKS = entrada.nextLine();
                ubicacioKS = "C:\\Users\\diego\\Desktop\\BMO\\M09\\UF1\\Ex03\\ArteagaDiegoA3.jks"
                //System.out.print("Contrasenya del magatzem de claus: ");
                //passKS = entrada.nextLine();
                passKS = "ArteagaDiegoP"

                kstore = loadKeyStore(ubicacioKS, passKS)

                //Una vegada tenim la keyStore, obtenim la clau pública i la clau privada
                //Demanem alies
                //System.out.print("Introdueix l'alias: ");
                //alias = entrada.nextLine();
                alias = "arteagadiego"
                val cert = kstore.getCertificate(alias)
                pubKey = cert.publicKey
            }
            else {
                //Generem un parell de claus
                val keys = randomGenerate(1024)
                pubKey = keys!!.public
                priKey = keys.private
            }

            encriptat = encryptData(btext, pubKey)
            val encriptatHexa = bytesToHex(encriptat)
            println("Text encriptat $encriptatHexa")
        } else if (opcio == 2) {
            //DESXIFRAR
            text = demanarText()
            btext = hexStringToByteArray(text)

            val magatzem:Boolean = demanarMagatzemClaus()
            if (magatzem) {
                //System.out.print("Dona'm l'ubicació del magatzem de claus: ");
                //ubicacioKS = entrada.nextLine();
                ubicacioKS = "C:\\Users\\diego\\Desktop\\BMO\\M09\\UF1\\Ex03\\ArteagaDiegoA3.jks"
                //System.out.print("Contrasenya del magatzem de claus: ");
                //passKS = entrada.nextLine();
                passKS = "ArteagaDiegoP"
                kstore = loadKeyStore(ubicacioKS, passKS)
                //System.out.print("Introdueix l'alias: ");
                //alias = entrada.nextLine();
                alias = "arteagadiego"
                priKey = kstore.getKey(alias, passKS.toCharArray()) as PrivateKey
            }
            else {
                //El parell de claus ja va ser generat en el moment de xifrar. Cal mantenir-lo
            }

            decript = decryptData(btext, priKey)
            val textDesencriptat = String(decript!!)
            println("Text desencriptat: $textDesencriptat")
        }

        var sortir: Boolean = demanarSortir()

    } while (!sortir)
}

//Funció per encriptar el text fent servir la clau pública
fun encryptData(data: ByteArray?, pub: PublicKey?): ByteArray? {
    var encryptedData: ByteArray? = null
    try {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, pub)
        encryptedData = cipher.doFinal(data)
    } catch (ex: Exception) {
        System.err.println("Error xifrant: $ex")
    }
    return encryptedData
}

//Desencriptem fent servir la clau privada
fun decryptData(data: ByteArray?, priv: PrivateKey?): ByteArray? {
    var decryptedData: ByteArray? = null
    try {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, priv)
        decryptedData = cipher.doFinal(data)
    } catch (ex: Exception) {
        System.err.println("Error xifrant: $ex")
    }
    return decryptedData
}

//Funció per carregar el magatzem de claus
@Throws(Exception::class)
fun loadKeyStore(ksFile: String?, ksPwd: String): KeyStore {
    val ks = KeyStore.getInstance("JKS")
    val f = File(ksFile)
    if (f.isFile) {
        val fis = FileInputStream(f)
        ks.load(fis, ksPwd.toCharArray())
    }
    return ks
}

// Genera un parell de claus de forma aleatòria
fun randomGenerate(len: Int): KeyPair? {
    var keys: KeyPair? = null
    try {
        val kgen = KeyPairGenerator.getInstance("RSA")
        kgen.initialize(len)
        keys = kgen.genKeyPair()
    } catch (ex: java.lang.Exception) {
        System.err.println("Generador no disponible.")
    }
    return keys
}