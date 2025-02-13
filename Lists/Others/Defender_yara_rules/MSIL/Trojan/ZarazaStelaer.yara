rule Trojan_MSIL_ZarazaStelaer_CTP_2147843454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZarazaStelaer.CTP!MTB"
        threat_id = "2147843454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZarazaStelaer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 70 00 69 00 2e 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 62 00 6f 00 74 00 00 5d 36 00 30 00 30 00 37 00 34 00 30 00 32 00 37 00 32 00 39 00 3a 00 41 00 41 00 45 00 50 00 62 00 30 00 6b 00 30 00 65 00 63 00 5f 00 45 00 69 00 64 00 32 00 67 00 78 00 7a 00 77 00 65 00 53 00 57 00 75 00 4e 00 6a 00 75 00 2d 00 64 00 57 00 68 00 48 00 69 00 63 00 53 00 30 00 00 2b 2f 00 73 00 65 00 6e 00 64 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 3f 00 63 00 68 00 61 00 74 00 5f 00 69 00 64 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = "\\Google\\Chrome\\User Data" wide //weight: 1
        $x_1_3 = "\\AVAST Software\\Browser\\User Data" wide //weight: 1
        $x_1_4 = "Opera Software\\Opera Stable" wide //weight: 1
        $x_1_5 = "BraveSoftware\\Brave-Browser\\User Data" wide //weight: 1
        $x_1_6 = "Blisk\\User Data" wide //weight: 1
        $x_1_7 = "Sputnik\\Sputnik\\User Data" wide //weight: 1
        $x_1_8 = "Microsoft\\Edge\\User Data" wide //weight: 1
        $x_1_9 = "\\Login Data" wide //weight: 1
        $x_1_10 = "\\Ya Passman Data" wide //weight: 1
        $x_1_11 = "\\Ya Login Data" wide //weight: 1
        $x_1_12 = "encrypted_key\":\"(.*?)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

