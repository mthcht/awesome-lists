rule Trojan_Linux_Hiddad_A_2147829506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Hiddad.A!xp"
        threat_id = "2147829506"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Hiddad"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 ea 46 f9 f4 03 02 aa f7 03 00 aa 21 00 40 f9 a1 2f 00 f9 82 10 00 b4}  //weight: 1, accuracy: High
        $x_1_2 = {e1 03 14 aa e0 03 17 aa 42 ac 42 f9 40 00 3f d6 00 7c 40 93 e1 04 00 f0 25 30 44 b9}  //weight: 1, accuracy: High
        $x_1_3 = {c3 6a 61 38 42 00 03 4a c2 6a 21 38 21 04 00 91 e2 03 03 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Hiddad_B_2147830451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Hiddad.B!xp"
        threat_id = "2147830451"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Hiddad"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 d2 48 89 34 24 0f 84 d6 04 00 00 e8 49 c6 ff ff 48 89 df e8 21 da ff ff 41 89 c4}  //weight: 1, accuracy: High
        $x_1_2 = {e8 da d0 ff ff 48 8b 13 48 89 df 48 89 c6 ff 52 30 b9 39 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 8b 44 24 18 48 89 c1 48 8b 54 24 10 48 89 df 48 8b 34 24 e8 d7 e3 ff ff e9 5d fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

