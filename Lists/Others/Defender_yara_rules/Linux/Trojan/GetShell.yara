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

rule Trojan_Linux_GetShell_HAB_2147962720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/GetShell.HAB!MTB"
        threat_id = "2147962720"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {2f 62 69 6e 2f 62 61 73 68 00 52 53 48 20 54 45 53 54 20 45 4e 44 00}  //weight: 20, accuracy: High
        $x_15_2 = {00 69 6e 65 74 5f 61 64 64 72 00 70 75 74 73 00 5f 5f 73 74 61 63 6b 5f 63 68 6b 5f 66 61 69 6c 00 73 6f 63 6b 65 74 00 64 75 70 32 00 65 78 65 63 76 65 00 5f 5f 6c 69 62 63 5f 73 74 61 72 74 5f 6d 61 69 6e 00 5f 5f 63 78 61 5f 66 69 6e 61 6c 69 7a 65 00 63 6f 6e 6e 65 63 74 00 6c 69 62}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

