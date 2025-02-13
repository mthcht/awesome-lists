rule Trojan_Java_Blacole_ZKM_2147665166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Blacole_ZKM"
        threat_id = "2147665166"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Blacole_ZKM"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 10 00 bc 08 3a ?? 03 36 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {10 41 10 5a b6 ?? ?? 36 04 [0-42] 10 41 a1 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {10 5a 36 0a 10 4d 36}  //weight: 1, accuracy: High
        $x_1_4 = {a7 00 04 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

