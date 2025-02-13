rule TrojanDownloader_Java_Classloader_E_2147693050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Classloader.E"
        threat_id = "2147693050"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Classloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 2e 41 74 6f 6d ?? ?? ?? ?? (61|2d|7a) (61|2d|7a) [0-18] 69 63 52 65 66 00 01 65 72 65 6e [0-255] 67 65 74 [0-4] 00 01 [0-6] 4c 6f 61 64 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

