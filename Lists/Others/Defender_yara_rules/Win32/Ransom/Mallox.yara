rule Ransom_Win32_Mallox_AD_2147852013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mallox.AD!MTB"
        threat_id = "2147852013"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 62 ff 8a 02 8a 4a 01 8a 6a 02 88 65 ?? 88 45 ?? 88 4d ?? 88 6d ?? f6 c3 ?? 75 ?? 0f b6 c8 0f b6 45 ?? 8a 80 ?? ?? ?? ?? 88 45 ?? 0f b6 45 ?? 8a 80 ?? ?? ?? ?? 88 45 ?? 0f b6 45 ?? 8a 80 ?? ?? ?? ?? 88 45}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c3 c1 e8 02 8a a0 ?? ?? ?? ?? 32 a1 ?? ?? ?? ?? 8a 4d ?? 8a 6d ?? 8a 42 ?? 32 c4 88 42 ?? 8a 42 ?? 32 45 ?? 88 42 ?? 8a 42 ?? 32 c1 88 42 ?? 8a 42 ?? 32 c5 43 88 42 ?? 83 c2 04 83 fb ?? 0f 82}  //weight: 10, accuracy: Low
        $x_10_3 = {8a 1c 03 8b 4d ?? 8a 14 01 8a 08 88 5d ?? 8b 5d ?? 8a 1c 03 88 5d ?? 75 ?? 0f b6 db 8a 9b ?? ?? ?? ?? 0f b6 c9 88 55 ?? 8a 91 ?? ?? ?? ?? 0f b6 4d ?? 8a 89 ?? ?? ?? ?? 88 5d ?? 0f b6 5d ?? 8a 9b ?? ?? ?? ?? 88 5d ?? 8b 5d ?? c1 eb ?? 32 93 ?? ?? ?? ?? 8b 5d}  //weight: 10, accuracy: Low
        $x_10_4 = {8a 1c 33 32 da 8b 55 ?? 88 1c 3a 8a 50 ?? 32 d1 88 50 ?? 8a 0e 32 4d ?? 83 c0 04 88 4e ?? 8b 4d ?? 8a 0c 31 32 4d ?? ff 45 ?? 88 0f 83 c6 04 83 c7 04 83 7d ?? ?? 0f 82}  //weight: 10, accuracy: Low
        $x_100_5 = "\\sysnative\\vssadmin.exe" wide //weight: 100
        $x_100_6 = "delete shadows /all /quiet" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Mallox_DA_2147918847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mallox.DA!MTB"
        threat_id = "2147918847"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cant send target info data to the server" ascii //weight: 1
        $x_1_2 = "HOW TO DECRYPT.txt" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "vssadmin.exe" ascii //weight: 1
        $x_1_5 = "taskkill.exe" ascii //weight: 1
        $x_1_6 = ".mallox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

