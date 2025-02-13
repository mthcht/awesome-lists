rule Ransom_Win32_Lokbit_AA_2147818444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lokbit.AA!MTB"
        threat_id = "2147818444"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a ?? 68 02 10 04 00 ff d0 8b f0}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 1a 00 00 00 be 41 00 00 ?? 6a 5c ff 75 ?? ff 15 ?? ?? ?? ?? 83 c4 08 83 c0 02}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 0c 41 33 d2 f7 f1 92 3b 45 08}  //weight: 1, accuracy: High
        $x_2_4 = {33 c0 40 c1 e0 06 8d 40 f0 64 8b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

