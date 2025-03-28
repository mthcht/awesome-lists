rule Ransom_Win32_GrandCrab_A_2147741209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GrandCrab.A"
        threat_id = "2147741209"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GrandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = "cozame vijiha rabemebopoboze harupuyucite fuvukuyidediye juyiwadu toxazepa yuwenesihuho sicefu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_GrandCrab_SA_2147743514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GrandCrab.SA!MSR"
        threat_id = "2147743514"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GrandCrab"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "92.63.197.60" ascii //weight: 1
        $x_1_2 = "pakludkosa" ascii //weight: 1
        $x_1_3 = "123.56.228.49" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_GrandCrab_CR_2147744199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GrandCrab.CR!MTB"
        threat_id = "2147744199"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GrandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 ff d3 8d 45 ?? 50 ff 15 ?? ?? ?? 00 8d 4d ?? 51 6a 00 6a 00 ff 15 ?? ?? ?? 00 e8 ?? ?? ?? ?? 30 04 3e 46 3b 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 85 27 fb ff ff 50 88 85 2d fb ff ff 88 85 23 fb ff ff 88 85 2a fb ff ff c6 85 2c fb ff ff 63 88 8d 22 fb ff ff c6 85 2e fb ff ff 00 33 f6 8d 9b 00 00 00 00 81 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GrandCrab_DA_2147745743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GrandCrab.DA!MTB"
        threat_id = "2147745743"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GrandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b bd f0 f7 ff ff ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? e8 8f ff ff ff 30 04 1f 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 33 c0 89 b5 e8 f7 ff ff 8d bd ec f7 ff ff ab 8d 85 e8 f7 ff ff 50 56 56 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {75 40 39 74 24 ?? 75 34 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6b 65 72 6e c7 05 ?? ?? ?? ?? 65 6c 33 32 c7 05 ?? ?? ?? ?? 2e 64 6c 6c c6 05 ?? ?? ?? ?? 00 ff 15 ?? ?? ?? ?? 89 44 24 ?? 47 e9 61 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GrandCrab_PCC_2147787689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GrandCrab.PCC!MTB"
        threat_id = "2147787689"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GrandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kis is running..." ascii //weight: 1
        $x_1_2 = "avoiding sandbox by sleeping 60 secs" ascii //weight: 1
        $x_1_3 = "F-Secure either Symantec is running" ascii //weight: 1
        $x_1_4 = "Disable Comodo" wide //weight: 1
        $x_1_5 = "GandCrab!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GrandCrab_SAA_2147937161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GrandCrab.SAA!MTB"
        threat_id = "2147937161"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GrandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 1e 2b 75 e8 33 c8 2b f9 83 6d fc 01}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

