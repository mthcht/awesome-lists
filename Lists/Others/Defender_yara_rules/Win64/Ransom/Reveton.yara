rule Ransom_Win64_Reveton_B_2147686755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Reveton.B"
        threat_id = "2147686755"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 f8 3c 72 62 48 8d 8d ?? ?? ?? ?? c7 c2 00 00 00 02 4d 33 c0 44 8b 8d ?? ?? ?? ?? 48 8b 85}  //weight: 10, accuracy: Low
        $x_1_2 = "work" wide //weight: 1
        $x_1_3 = "NtCreateThreadEx" wide //weight: 1
        $x_1_4 = "SVCHOST.EXE" wide //weight: 1
        $x_1_5 = ".cpp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

