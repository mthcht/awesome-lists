rule Trojan_Linux_PondRat_A_2147922949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PondRat.A!MTB"
        threat_id = "2147922949"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PondRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jdkgradle.com" ascii //weight: 1
        $x_1_2 = {31 c0 48 8b 5c 24 18 48 8b 6c 24 20 4c 8b 64 24 28 4c 8b 6c 24 30 4c 8b 74 24 38 4c 8b 7c 24 40 48 83 c4 48 c3 0f 1f 00 4c 89 ef e8 d0 e7 ff ff 31 c0}  //weight: 1, accuracy: High
        $x_1_3 = {4c 89 ef e8 ed ec ff ff 31 c0 83 3b 00 0f 94 c0 48 81 c4 a0 01 00 00 5b 5d 41 5c 41 5d 41 5e c3 0f 1f 44 00 00 48 81 c4 a0 01 00 00 b8 01 00 00 00 5b 5d 41 5c 41 5d 41 5e c3 0f 1f 00 b9 40 89 84 00 ba 00 89 84 00 be 1d 1e 59 00 48 89 e7 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

