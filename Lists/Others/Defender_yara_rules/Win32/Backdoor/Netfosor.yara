rule Backdoor_Win32_Netfosor_F_2147697370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Netfosor.F!dha"
        threat_id = "2147697370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Netfosor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {da d4 d9 74 24 f4 5b bf ?? ?? ?? ?? 29 c9 66 b9 ?? ?? 83 eb fc}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 53 6a 00 ff 15 [0-13] 8d 45 fc 50 6a 40 6a 10 53 ff 15 ?? ?? ?? ?? 85 c0 74 2d b8 ?? ?? ?? ?? 8b c8 2a cb 80 e9 05 2b c3 88 4b 01 83 c0 fb 8b c8 c1 f9 08 88 4b 02 8b c8 c1 f9 10 c1 f8 18 c6 03 e9 88 4b 03 88 43 04 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

