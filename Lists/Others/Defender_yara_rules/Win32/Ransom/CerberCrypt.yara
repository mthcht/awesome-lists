rule Ransom_Win32_CerberCrypt_SU_2147766735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CerberCrypt.SU!MTB"
        threat_id = "2147766735"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 3b 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 33 33 c8 8d 9b}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f9 ff 4d ?? 75 ?? 8b 45 ?? 8b 5d ?? 89 38 8b 45 ?? 89 30 8b 45 ?? 40 89 45 ?? 3b 45 ?? 0f 82 ?? ff ff ff 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CerberCrypt_PA_2147781548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CerberCrypt.PA!MTB"
        threat_id = "2147781548"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 74 65 73 74 37 5c [0-16] 5c 74 65 73 74 37 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 89 45 ?? 81 7d [0-6] 7d ?? 8b 45 ?? 99 b9 ?? ?? ?? ?? f7 f9 85 d2 74 ?? 0f b7 05 ?? ?? ?? ?? 05 c7 [0-3] 8b 0d ?? ?? ?? ?? 03 4d ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ?? 88 10 eb ?? 0f b7 ?? ?? ?? ?? ?? 05 c9 [0-3] 8b 0d ?? ?? ?? ?? 03 4d ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CerberCrypt_PB_2147793455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CerberCrypt.PB!MTB"
        threat_id = "2147793455"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 01 8b 55 ?? 81 c2 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 33 10 8b 4d ?? 03 4d ?? 89 11 eb ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CerberCrypt_PAA_2147796640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CerberCrypt.PAA!MTB"
        threat_id = "2147796640"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tor2web.org" ascii //weight: 1
        $x_1_2 = "remove_shadows" ascii //weight: 1
        $x_1_3 = "CERBER RANSOMWARE" ascii //weight: 1
        $x_1_4 = "\".vbox\",\".vdi\"" ascii //weight: 1
        $x_1_5 = "important files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

