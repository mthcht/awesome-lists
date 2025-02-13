rule Ransom_Win32_Rolsig_A_2147780410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rolsig.A"
        threat_id = "2147780410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rolsig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 8b c3 43 8b ca 83 e0 01 8b c2 75 0b c1 e1 05 d1 e8 33 c8 33 ce eb 0c c1 e1 09 c1 e8 03 33 c8 33 ce f7 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Rolsig_A_2147780410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rolsig.A"
        threat_id = "2147780410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rolsig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HardwareBreakpoints" ascii //weight: 1
        $x_1_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 (50|41)}  //weight: 1, accuracy: Low
        $x_1_3 = "CheckRemoteDebuggerPresentAPI" ascii //weight: 1
        $x_1_4 = "IsAnyDebuggerPresent" ascii //weight: 1
        $x_1_5 = "Pippo Container Client" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Rolsig_B_2147781383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rolsig.B"
        threat_id = "2147781383"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rolsig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 81 23 9e 6f 8b ?? e8 ?? ?? ?? ?? ba 60 cb da 25 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba b9 86 56 26 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 3b 20 40 64 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 89 49 46 6a a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 8f 91 f4 75 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 11 b3 31 45 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 87 bb 3b 6a a3}  //weight: 1, accuracy: Low
        $x_1_2 = {ba b7 e6 7b 6e 8b ?? e8 ?? ?? ?? ?? ba 02 1b a3 41 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba f1 67 85 46 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 00 a5 37 65 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba c3 b1 f3 3b a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 4c 32 94 03 a3 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? ba 81 e9 18 4c a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

