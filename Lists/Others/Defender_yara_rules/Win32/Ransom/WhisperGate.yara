rule Ransom_Win32_WhisperGate_K_2147810470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WhisperGate.K!dha"
        threat_id = "2147810470"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 ?? ?? ?? ?? 8b ?? ?? 89 04 24 e8 ?? ?? ?? ?? 89 45 ?? c7 04 24 00 00 10 00 e8 ?? ?? ?? ?? 89 45 ?? c7 44 24 08 00 00 10 00 c7 44 24 04 cc 00 00 00 8b 45 ?? 89 04 24 e8 ?? ?? ?? ?? 8b 45 ?? 89 44 24 0c c7 44 24 08 00 00 10 00 c7 44 24 04 01 00 00 00 8b 45 ?? 89 04 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WhisperGate_MFP_2147810982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WhisperGate.MFP!MTB"
        threat_id = "2147810982"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 00 8c c8 8e d8 be 88 7c e8 00 00 50 fc 8a 04 3c 00 74 06 e8 05 00 46 eb f4 eb 05 b4 0e cd 10}  //weight: 1, accuracy: High
        $x_1_2 = "\\PhysicalDrive0" ascii //weight: 1
        $x_1_3 = "Your hard drive has been corrupted" ascii //weight: 1
        $x_1_4 = "bitcoin wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

