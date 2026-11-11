rule Trojan_Linux_Plex2Shell_DA_2147981891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Plex2Shell.DA!MTB"
        threat_id = "2147981891"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Plex2Shell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {a9 17 12 9b 08 9e 69 b1 b5 d3 8b a0 ed 83 4a a8 e2 86 55 ac c7 48 f4 a0 61 27 0f 69 60 22 6c 57 53 b2 a3 b2 91 4e d9 63 c9 40 c2 3b 95 33 7e bd f9 90 e3 25 c5 48 48 2f a8 50 19 26 2c cf 39 79 a7 ec e5 b9 73 73 a3 24 f4 3f e5 7a af 8a c7 58 10 e3 d9 65 f5 a7 7b 18 c5 d3 e5 51 46 55 cb ae 14 a4 01 db 94 04 f7 2c 90 8b bc 4e 6d 51}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

