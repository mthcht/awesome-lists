rule Backdoor_Win32_Leenx_A_2147655268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Leenx.A"
        threat_id = "2147655268"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Leenx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ?? ?? 40 3d ?? ?? 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {56 8b ff b9 ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8b fb f3 a5 8b ff 8d 45 ?? 50 6a 00 6a 00 53 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

