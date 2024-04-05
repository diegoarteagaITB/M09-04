import java.util.*

//Scanner global
val sc = Scanner(System.`in`)

fun demanarMode(): Int {
    var first : Boolean = true
    var mode: Int
    do {
        if (first) {
            print("Mode - (1) Encriptar, (2) Desencriptar: ")
            first = false
        } else print("Mode incorrecte. Tria (1) Encriptar, (2) Desencriptar: ")
        val modeString = sc.nextLine()
        mode = try {
            modeString.toInt()
        } catch (e: Exception) {
            0
        }
    } while (mode != 1 && mode != 2)
    return mode
}
fun demanarMetodeClauSecreta(): String {
    var first = true
    var nameMethod: String
    do {
        if (first) {
            print("Mètode de clau secreta - (AES), (DES): ")
            first = false
        } else print("Mètode de clau secreta. Tria (AES) o (DES): ")
        nameMethod = sc.nextLine()
    } while (nameMethod != "AES" && nameMethod != "DES")
    return nameMethod
}
fun demanarMetodeBlock() :String    {
    var first:Boolean = true
    var blockMethod:String
    do
    {
        if (first) {
            print("Demanar mètode de bloc - (ECB), (CBC): ")
            first = false
        } else print("Mètode de bloc incorrecte. Tria (ECB) o (CBC): ")
        blockMethod = sc.nextLine()
    } while (blockMethod != "ECB" && blockMethod != "CBC")
    return blockMethod
}
fun demanarLongitudClau(metode: String): Int {
    var keyLength = 0
    if (metode == "DES") {
        keyLength = 64
    } else if (metode == "AES") {
        var first = true
        do {
            if (first) {
                print("Select an option. Key length - (128), (192) or (256): ")
                first = false
            } else print("Incorrect key length option. Select (128), (192) or (256): ")
            val keyLengthString = sc.nextLine()
            keyLength = try {
                keyLengthString.toInt()
            } catch (e: Exception) {
                0
            }
        } while (keyLength != 128 && keyLength != 192 && keyLength != 256)
    }
    return keyLength
}
fun demanarMetodeHash(metode: String, longClau: Int): String {
    var first:Boolean
    var hashMethod: String

    if (metode == "AES" && longClau > 128) hashMethod = "SHA-256"
    else {
        first = true
        do {
            if (first) {
                print("Mètode de hash - MD5, SHA-1 o SHA-256: ")
                first = false
            } else print("Mètode de hash incorrecte. Tria MD5, SHA-1 o SHA-256: ")
            hashMethod = sc.nextLine()
        } while (hashMethod != "MD5" && hashMethod != "SHA-1" && hashMethod != "SHA-256")
    }
    return hashMethod
}
fun demanarPassword(): String {
    print("Password: ")
    return sc.nextLine()
}
fun demanarText(): String {
    print("Text: ")
    return sc.nextLine()
}
fun demanarSortir(): Boolean {
    var sortir = false
    var first = true
    do {
        if (first) {
            print("Sortir? (S/N): ")
            first = false
        } else print("Tria (S) o (N): ")
        val sortirString = sc.nextLine().uppercase()
        if (sortirString == "S") sortir = true
        else if (sortirString == "N") sortir = false
    } while (sortirString != "S" && sortirString != "N")
    return sortir
}
fun demanarMagatzemClaus(): Boolean {
    var sortir = false
    var first = true
    do {
        if (first) {
            print("Vols fer servir el magatzem de claus? (S/N): ")
            first = false
        } else print("Tria (S) o (N): ")
        val sortirString = sc.nextLine().uppercase()
        if (sortirString == "S") sortir = true
        else if (sortirString == "N") sortir = false
    } while (sortirString != "S" && sortirString != "N")
    return sortir
}



// Funció per convertir de String a Array de Bytes
fun hexStringToByteArray(s:String) : ByteArray {
    return s.decodeHex()
}
fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
// Funció per convertir d'Array de Bytes a String
fun bytesToHex(bytes: ByteArray?): String {
    val hex = HexFormat.of().formatHex(bytes)
    return hex.uppercase()
}