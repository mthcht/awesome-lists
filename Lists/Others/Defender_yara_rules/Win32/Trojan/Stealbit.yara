rule Trojan_Win32_Stealbit_RB_2147833852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealbit.RB!MTB"
        threat_id = "2147833852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 78 00 c7 44 24 ?? 76 00 2e 00 [0-21] c7 44 24 ?? 2f 00 25 00 c7 44 24 ?? 64 00 2e 00 [0-21] c7 44 24 ?? 6d 00 6c 00 [0-21] c7 44 24 ?? 74 00 70 00 c7 44 24 ?? 3a 00 2f 00 c7 44 24 ?? 2f 00 78 00 c7 44 24 ?? 76 00 2e 00 [0-21] c7 44 24 ?? 2f 00 6c 00 c7 44 24 ?? 6f 00 67 00 c7 84 24 ?? 00 00 00 6f 00 2e 00 c7 84 24 ?? 00 00 00 70 00 6e 00 c7 84 24 ?? 00 00 00 67 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

