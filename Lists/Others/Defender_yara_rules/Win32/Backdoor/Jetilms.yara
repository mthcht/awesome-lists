rule Backdoor_Win32_Jetilms_A_2147648324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jetilms.A"
        threat_id = "2147648324"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jetilms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ec 08 6a 2d 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 c4 10 83 ec 08}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d0 c1 e8 1f 01 d0 d1 f8 3b 45 ?? 7f ?? c7 45 ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 02 00 00 0f 8f ?? ?? 00 00 8b 4d ?? 8b 45 ?? c1 e0 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

