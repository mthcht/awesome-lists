rule Ransom_Win32_Play_NEAA_2147836705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Play.NEAA!MTB"
        threat_id = "2147836705"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Play"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 8d c0 fd ff ff 83 e9 01 89 8d c0 fd ff ff 83 bd c0 fd ff ff 00 0f 8e 84 01 00 00 8b 95 b4 fd ff ff 8b 42 28 8b 8d c0 fd ff ff 0f b7 14 48 83 fa 5c 0f 85}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Play_PAA_2147841923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Play.PAA!MTB"
        threat_id = "2147841923"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Play"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8b 4c 24 ?? 0b c8 8b 4c 24 ?? 75 ?? 8b 44 24 04 f7 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e1 8b d8 8b 44 24 ?? f7 64 24 ?? 03 d8 8b 44 24 ?? f7 e1 03 d3 5b}  //weight: 1, accuracy: Low
        $x_1_3 = {53 f7 e1 8b d8 8b 44 24 ?? f7 64 24 ?? 03 d8 8b 44 24 ?? f7 e1 03 d3 5b}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 ?? 53 56 57 83 ec 08 b0 40 b3 73 3a c3 75 ?? 81 c4 ?? ?? ?? ?? 83 c4 08 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Play_AA_2147888336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Play.AA!MTB"
        threat_id = "2147888336"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Play"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NETWORK THREAD START ENCRYPTION:" ascii //weight: 1
        $x_1_2 = "EncryptLocalAndNetwork -1" ascii //weight: 1
        $x_1_3 = "InitProvidersImportPublicKey -1 CRITICAL" ascii //weight: 1
        $x_1_4 = "second step encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Play_ZA_2147904412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Play.ZA!MTB"
        threat_id = "2147904412"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Play"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d cc d3 e0 8b 4d d0 03 4d d4 0f b6 11 0b d0 8b 45 d0 03 45 d4 88 10 e9}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 d0 03 45 d4 0f b6 08 33 ca 8b 55 d0 03 55 d4 88 0a eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

