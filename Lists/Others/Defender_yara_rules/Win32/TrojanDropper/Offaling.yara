rule TrojanDropper_Win32_Offaling_A_2147744091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Offaling.A!dha"
        threat_id = "2147744091"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Offaling"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 33 c9 ff 15 ?? 04 00 00 33 c9 ff 15 ?? 04 00 00 33 c9 ff 15 ?? 04 00 00 b8 01 00 00 00 48 83 c4 28 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "69FF0000FD0841C1EB104569DB03F76523412BFB81EFFB12B71C" ascii //weight: 1
        $x_1_3 = {6d 73 63 6f 72 65 65 2e 64 6c 6c 00 43 6f 72 42 69 6e 64 54 6f 52 75 6e 74 69 6d 65 45 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

