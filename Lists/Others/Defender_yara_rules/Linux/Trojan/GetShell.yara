rule Trojan_Linux_GetShell_C_2147899551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/GetShell.C!MTB"
        threat_id = "2147899551"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 48 98 48 8d 14 c5 00 00 00 00 48 8b 45 e0 48 01 d0 48 8b 00 48 89 c7 e8 5d fc ff ff 48 89 c2 8b 45 fc 48 98 48 8d 0c c5 00 00 00 00 48 8b 45 e0 48 01 c8 48 8b 00 be 20 00 00 00 48 89 c7 e8 76 fc ff ff 83 45 fc 01 8b 45 fc 3b 45 ec 7c ae}  //weight: 1, accuracy: High
        $x_1_2 = {74 1e 0f 1f 84 00 00 00 00 00 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea 48 83 c4 08}  //weight: 1, accuracy: High
        $x_1_3 = {e8 12 fd ff ff 85 c0 75 19 be bf 88 00 00 bf cc 0c 40 00 e8 0c fe ff ff bf 00 00 00 00 e8 b5 fc ff ff bf 23 00 00 00 e8 db fc ff ff eb d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_GetShell_H_2147945395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/GetShell.H!MTB"
        threat_id = "2147945395"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 45 31 c0 31 c9 48 8d 3d 01 ff ff ff ff 15 b3 2d 00 00 f4}  //weight: 1, accuracy: High
        $x_1_2 = {80 3d 65 2d 00 00 00 75 2b 55 48 83 3d 42 2d 00 00 00 48 89 e5 74 0c 48 8b 3d 46 2d 00 00 e8 d9 fd ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {31 f6 89 df e8 3a ff ff ff be 01 00 00 00 89 df e8 2e ff ff ff be 02 00 00 00 89 df e8 22 ff ff ff 48 8d 3d 6b 10 00 00 31 c0 31 d2 48 8d 74 24 08 48 89 7c 24 08 48 89 44 24 10 e8 13 ff ff ff 48 8d 3d 56 10 00 00 e8 d7 fe ff ff 48 8b 44 24 28 64 48 2b 04 25 28 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

