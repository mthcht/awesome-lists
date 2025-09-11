rule Trojan_Win32_Radthief_GVA_2147935569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radthief.GVA!MTB"
        threat_id = "2147935569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 cc 30 04 37 46 8b 45 d8 8b 7d d4 83 45 c4 11 89 45 bc 2b c7 89 75 b4 3b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radthief_SX_2147948886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radthief.SX!MTB"
        threat_id = "2147948886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 00 01 f0 ff e0 31 c0 81 fb ?? ?? ?? ?? 0f 9c c0 c1 e0 ?? 8b 80 ?? ?? ?? ?? 01 f0 ff e0 31 c0}  //weight: 3, accuracy: Low
        $x_2_2 = {0f 4c c7 8b 00 01 f0 89 d7 8b 54 24 ?? 89 54 24 ?? 89 fa ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radthief_LM_2147951973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radthief.LM!MTB"
        threat_id = "2147951973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b d0 c1 ea 1e 33 d0 69 c2 65 89 07 6c 03 c1 89 44 8c 04 41 81 f9 70 02 00 00 72 ?? 8b 84 24 94 13 00 00 8d 0c 24 56 8b b4 24 94 13 00 00 35 00 00 00 80 81 f6 00 00 00 80 c7 44 24 04 70 02 00 00 2b c6 83 f8 ff}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radthief_AR_2147952016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radthief.AR!MTB"
        threat_id = "2147952016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 ea 1e 33 d0 69 c2 ?? ?? ?? ?? 03 c1 89 44 8c 04 41 81 f9}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 45 c8 8b 4d cc 89 45 c0 89 4d c4 ff d7 2b 45 d0 1b 55 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

