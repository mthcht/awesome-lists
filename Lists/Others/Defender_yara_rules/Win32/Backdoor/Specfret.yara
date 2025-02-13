rule Backdoor_Win32_Specfret_A_2147639904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Specfret.A"
        threat_id = "2147639904"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Specfret"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d b5 6c f8 ff ff 8d bd d0 f8 ff ff f3 a5 68 10 27 00 00 e8 ?? ?? ?? ?? 83 c4 08 05 00 78 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

