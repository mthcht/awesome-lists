rule TrojanDropper_Win32_Fetrog_A_2147691826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fetrog.A"
        threat_id = "2147691826"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fetrog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 d2 6d a9 33 60 b8 8f 3b 48 dd 2b c2 8b d0 c1 e8 08 30 01}  //weight: 10, accuracy: High
        $x_1_2 = {68 00 24 89 85 51 c7 44 24 ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 10 81 7c 24 ?? 00 10 00 00 75 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

