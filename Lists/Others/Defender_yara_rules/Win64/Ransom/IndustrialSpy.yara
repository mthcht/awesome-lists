rule Ransom_Win64_IndustrialSpy_A_2147850585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/IndustrialSpy.A"
        threat_id = "2147850585"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "IndustrialSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 0a 64 65 c7 ?? ?? ?? 6c 20 25 31 c7 ?? ?? ?? 0d 0a 69 66 c7 ?? ?? ?? 20 6e 6f 74 c7 ?? ?? ?? 20 65 72 72 c7 ?? ?? ?? 6f 72 6c 65 c7 ?? ?? ?? 76 65 6c 20 c7 ?? ?? ?? 30 20 67 6f c7 ?? ?? ?? 74 6f 20 72 c7 ?? ?? ?? 65 70 0d 0a c7 ?? ?? ?? 64 65 6c 20}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0d 0a 3a c7 ?? ?? ?? 72 65 70 0d c7 ?? ?? ?? 0a 64 65 6c c7 ?? ?? ?? 20 25 31 0d c7 ?? ?? ?? 0a 69 66 20 c7 ?? ?? ?? 6e 6f 74 20 c7 ?? ?? ?? 65 72 72 6f c7 ?? ?? ?? 72 6c 65 76 c7 ?? ?? ?? 65 6c 20 30 c7 ?? ?? ?? 20 67 6f 74}  //weight: 1, accuracy: Low
        $x_2_3 = "temp.cmd %s" ascii //weight: 2
        $n_3_4 = {88 13 00 00 01 00 00 00 00 00 40 06 00 00 00 00 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f}  //weight: -3, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_IndustrialSpy_MA_2147850598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/IndustrialSpy.MA!MTB"
        threat_id = "2147850598"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "IndustrialSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "The Underground team welcomes you!" ascii //weight: 1
        $x_1_2 = "Your files are currently encrypted, they can be restored to their original state with a decryptor key that only we have" ascii //weight: 1
        $x_1_3 = "Attempting to recover data by your own efforts may result in data loss" ascii //weight: 1
        $x_1_4 = "stop MSSQLSERVER /f /m" ascii //weight: 1
        $x_1_5 = "password-protected documents from a bank" ascii //weight: 1
        $x_1_6 = {68 74 74 70 3a 2f 2f 75 6e 64 67 72 64 [0-128] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
        $x_1_7 = "!!readme!!!.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_IndustrialSpy_MKV_2147950811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/IndustrialSpy.MKV!MTB"
        threat_id = "2147950811"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "IndustrialSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 c1 e6 08 44 0b f0 8b c6 83 bb a0 00 00 00 00 44 89 75 ec 74 ?? 33 83 ?? 00 00 00 33 83 ?? 00 00 00 89 45 e0 41 8b c6 33 83 ?? 00 00 00 33 83 ?? 00 00 00 eb}  //weight: 3, accuracy: Low
        $x_4_2 = {c1 e8 10 88 41 05 8a 45 e4 41 c1 e8 08 44 88 41 06 4c 8b 45 ?? 88 41 07 44 3b ff 0f 82}  //weight: 4, accuracy: Low
        $x_1_3 = "readme.htm" ascii //weight: 1
        $x_1_4 = "Self deleting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

