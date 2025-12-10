rule Trojan_Win64_Muddywater_GVA_2147959129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Muddywater.GVA!MTB"
        threat_id = "2147959129"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "194.11.246.101:443" ascii //weight: 5
        $x_1_2 = "SOFTWARE\\Microsoft\\Cryptography" ascii //weight: 1
        $x_1_3 = "main.runRemoteProxyRelay" ascii //weight: 1
        $x_1_4 = "main.GenerateCA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Muddywater_GVB_2147959162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Muddywater.GVB!MTB"
        threat_id = "2147959162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 5d e8 ff 15 77 ee 00 00 4c 8b c3 ba 08 00 00 00 48 8b c8 ff 15 56 ee 00 00 48 8b 4d d8 4c 8b c6 48 8b d8 48 8b d7 48 8d 45 e8 4c 8b cb 48 89 44 24 28 48 8b 45 e8 48 89 44 24 20 ff 15 be ea 02 00 85 c0 74 49}  //weight: 2, accuracy: High
        $x_1_2 = {42 0f b6 04 01 ff c2 88 01 48 8d 49 01 48 63 c2 49 3b c1 72 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Muddywater_GVC_2147959163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Muddywater.GVC!MTB"
        threat_id = "2147959163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 85 08 02 00 00 48 ff c0 48 89 85 08 02 00 00 48 8b 85 88 01 00 00 48 39 85 08 02 00 00 73 35 48 8b 85 08 02 00 00 48 8b 8d 68 01 00 00 48 03 c8 48 8b c1 0f b6 00 33 85 44 01 00 00 48 8b 8d 08 02 00 00 48 8b 95 68 01 00 00 48 03 d1 48 8b ca 88 01 eb aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Muddywater_GVD_2147959190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Muddywater.GVD!MTB"
        threat_id = "2147959190"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 8d 49 01 f7 eb 8b cb ff c3 d1 fa 8b c2 c1 e8 1f 03 d0 8d 04 92 2b c8 48 63 c1 42 0f b6 4c 0c 4f 42 2a 0c 10 43 88 4c 01 ff 83 fb 3b 72 cc}  //weight: 2, accuracy: High
        $x_1_2 = "\\logins.json" ascii //weight: 1
        $x_1_3 = "encrypted_key" ascii //weight: 1
        $x_1_4 = "\\Default\\Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

