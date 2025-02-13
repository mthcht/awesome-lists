rule TrojanSpy_Win32_Fitmu_A_2147801497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fitmu.A"
        threat_id = "2147801497"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fitmu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 15 74 28 83 f8 19 74 1c 83 f8 6e 74 10}  //weight: 1, accuracy: High
        $x_1_2 = {74 08 41 83 f9 02 72 db eb 0a 8b 7c cc 14 46 83 fe 05 74 0f}  //weight: 1, accuracy: High
        $x_1_3 = {2b f0 8a 14 06 30 94 04 ?? ?? ?? ?? 40 3b c1 7c f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

