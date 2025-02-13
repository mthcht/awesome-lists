rule Ransom_Win32_Stealbit_PA_2147788375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stealbit.PA!MTB"
        threat_id = "2147788375"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 81 ec [0-4] f6 40 68 70 56 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 8b c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 f9 7c 72 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

