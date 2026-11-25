rule Trojan_Linux_ZQAgent_DA_2147982754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ZQAgent.DA!MTB"
        threat_id = "2147982754"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ZQAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {3f d4 73 3d a4 c5 e5 a4 a4 8e f0 10 6c aa 18 f6 7c c9 11 fe ce d2 63 b6 4c 9a 5c 51 ef 93 5b da 0e f7 31 6b 75 93 ad 50 b2 4d 07 ca 58 ad 12 c8 33 8a 81 84 ba dc 74 05 51 20 88 09 b5 c5 03 8b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

