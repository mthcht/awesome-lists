rule Ransom_Win64_Ryuk_PA_2147734632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.PA!MTB"
        threat_id = "2147734632"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RyukReadMe.txt" wide //weight: 1
        $x_1_2 = "RyukReadMe.html" wide //weight: 1
        $x_1_3 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 1
        $x_1_4 = ".RYK" wide //weight: 1
        $x_1_5 = "keystorage2" wide //weight: 1
        $x_1_6 = "taskkill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Ryuk_PB_2147750052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.PB!MTB"
        threat_id = "2147750052"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8a 02 45 03 cb 41 28 00 4d 8d 52 04 4d 03 c3 41 83 f9 0c 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b c0 45 03 c7 99 f7 fe 48 63 c2 8a 4c 84 20 41 28 09 4d 03 cf 45 3b c2 7c e5}  //weight: 1, accuracy: High
        $x_1_3 = {41 8b c2 41 ff c2 99 41 f7 fb 48 63 ca 0f b7 14 8b 66 41 29 10 4d 8d 40 02 45 3b d1 7c e2}  //weight: 1, accuracy: High
        $x_1_4 = {41 0f b6 08 4c 03 c6 8b c1 83 e1 0f 48 c1 e8 04 42 8a 04 10 88 42 ff 42 8a 04 11 88 02 48 8d 52 02 4c 2b ce 75 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Ryuk_PC_2147750053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.PC!MTB"
        threat_id = "2147750053"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 74 8b 4c 24 10 8b f5 c1 ee 05 03 74 24 7c 03 f8 03 cd 33 f9 81 3d ?? ?? ?? ?? 72 07 00 00 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {06 ee a0 db c7 05 ?? ?? ?? ?? ff ff ff ff 33 f7 29 74 24 60 89 5c 24 14 81 f3 07 eb dd 13 81 6c 24 14 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 14 68 19 2a 14 81 44 24 14 be 08 9a 76 8b 5c 24 60 8b 4c 24 14 8b fb d3 e7 03 7c 24 6c 81 3d ?? ?? ?? ?? 1a 0c 00 00 75}  //weight: 10, accuracy: Low
        $x_1_3 = {8b fd c1 e7 04 81 3d ?? ?? ?? ?? a2 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Ryuk_E_2147752070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.E!MSR"
        threat_id = "2147752070"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TakDfLdvHuWdPxREXDROEs7XCoMA" ascii //weight: 1
        $x_1_2 = "GetMonitorInfoA" ascii //weight: 1
        $x_1_3 = "TestGdipButton.EXE" wide //weight: 1
        $x_1_4 = "iCCPPhotoshop ICC profile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Ryuk_PD_2147753134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.PD!MTB"
        threat_id = "2147753134"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c9 41 f7 e9 [0-3] 41 ff c1 c1 fa ?? 8b c2 c1 e8 1f 03 d0 69 c2 ?? ?? 00 00 2b c8 48 63 c1 8a 84 30 ?? ?? ?? 00 41 30 02 49 ff c2 41 81 f9 ?? ?? 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {41 f6 c2 01 75 06 41 8a 04 29 eb ?? 41 8b c3 41 8b ca 41 f7 ea [0-3] c1 fa ?? 8b c2 c1 e8 1f 03 d0 6b c2 ?? 2b c8 48 63 c1 8a 84 30 ?? ?? ?? 00 41 30 84 31 ?? ?? ?? 00 41 ff c2 49 ff c1 41 83 fa ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Ryuk_PG_2147772840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.PG!MTB"
        threat_id = "2147772840"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RyukReadMe.html" wide //weight: 1
        $x_1_2 = ".RYK" wide //weight: 1
        $x_1_3 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "ntaskkill" wide //weight: 1
        $x_1_5 = "cmd.exe /c \"WMIC.exe shadowcopy delete" ascii //weight: 1
        $x_1_6 = "repacomre1972@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Ryuk_MKZ_2147928729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ryuk.MKZ!MTB"
        threat_id = "2147928729"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8b d1 2b d0 48 63 c2 49 63 d1 41 ff c1 0f b6 84 18 ?? ?? ?? ?? 41 32 00 49 ff c0 41 88 02 49 ff c2 49 63 c1 48 3d 0d 08 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

