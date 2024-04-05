import java.io.UnsupportedEncodingException
import java.security.*
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher

fun main() {
    var sortir: Boolean
    do {
        var mode: Int
        var nameMethod: String
        var blockMethod: String
        var keyLength: Int
        var hashMethod: String
        var password: String
        var text: String

        val modeInteractiu:Boolean = false
        if (modeInteractiu) {
            /* Mode interactiu */
            mode = demanarMode()
            nameMethod = demanarMetodeClauSecreta()
            blockMethod = demanarMetodeBlock()
            keyLength = demanarLongitudClau(nameMethod)
            hashMethod = demanarMetodeHash(nameMethod, keyLength)
            password = demanarPassword()
            text = demanarText()
        }
        else {
            /* Per automatitzar el procés */
            mode = demanarMode()
            nameMethod = "AES"
            blockMethod = "ECB"
            keyLength = 128
            hashMethod = "MD5"
            password = "pwd1234"
            text = demanarText()
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Transformar entrada: no cal si es fa amb fitxers
        var btext: ByteArray?
        btext = if (mode == 1) text.toByteArray() // Per convertir el text clar a bytes
        else hexStringToByteArray(text) // Per convertir el text xifrat en hexadecimal a bytes,

        val time = System.nanoTime() // Per mesurar el temps de procés.

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Clau de keyLength bits amb hash
        val key = generateKeyFromPassword(nameMethod, keyLength, hashMethod, password)

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Xifratge/Desxifratge
        val rtext = transformation(
            mode, key, btext, "$nameMethod/$blockMethod/PKCS5Padding"
        )
        println(nameMethod + "/" + blockMethod + "/PKCS5Padding " + " amb password generat amb " + hashMethod + ": " + (System.nanoTime() - time) / 1000 + " microsegons")

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Mostrar resultat: no cal si es fa amb fitxers
        if (mode == 1) println(bytesToHex(rtext)) //Per convertir el text xifrat en bytes a un String en format hexadecimal
        else if (mode == 2) println("Output: " + String(rtext!!)) //Per convertir el text clar en bytes a String

        sortir = demanarSortir()
    } while (!sortir)


}

// Funció per generar la clau a partir de la contrasenya, segons el mètode de hash
fun generateKeyFromPassword(
    cipheringMethod: String?,
    keyLength: Int,
    hashAlgorithm: String?,
    password: String
): SecretKey? {
    try {
        val md = MessageDigest.getInstance(hashAlgorithm)
        var clauHash = md.digest(password.toByteArray(charset("UTF-8")))
        clauHash = clauHash.copyOf(keyLength / 8)
        return SecretKeySpec(clauHash, cipheringMethod)
    } catch (e: NoSuchAlgorithmException) {
        System.err.println("Incorrect encryption algorithm")
    } catch (e: UnsupportedEncodingException) {
        System.err.println("Incorrect password encoding")
    }
    return null
}

fun generarClauAleatoria(keySize: Int = 256): SecretKey {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(keySize)
    return keyGenerator.generateKey()
}

//Mètode per xifrar o desxifrar
fun transformation(cmode: Int, key: SecretKey?, btext: ByteArray?, cipheringMethod: String): ByteArray? {
    try {
        val c = Cipher.getInstance(cipheringMethod)
        val aux = cipheringMethod.split("/".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        if (aux[1] == "ECB") c.init(cmode, key)
        else {
            var IV_PARAM = byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
            if (aux[0] == "DES") IV_PARAM = IV_PARAM.copyOf(8) // The IV should have the block length

            val iv = IvParameterSpec(IV_PARAM)
            c.init(cmode, key, iv)
        }
        return c.doFinal(btext)
    } catch (e: NoSuchAlgorithmException) {
        System.err.println("Incorrect encryption algorithm")
    } catch (e: NoSuchPaddingException) {
        System.err.println("Incorrect padding technique")
    } catch (e: InvalidKeyException) {
        System.err.println("Invalid key")
    } catch (e: InvalidAlgorithmParameterException) {
        System.err.println("Invalid IV")
    } catch (e: IllegalBlockSizeException) {
        System.err.println("Illegal block size")
    } catch (e: BadPaddingException) {
        System.err.println("Incorrect padding")
    }
    return null
}

