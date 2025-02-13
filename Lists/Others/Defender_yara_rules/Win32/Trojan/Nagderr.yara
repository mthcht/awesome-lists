rule Trojan_Win32_Nagderr_A_2147625413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nagderr.A"
        threat_id = "2147625413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nagderr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 74 0a 83 f8 03 74 05 83 f8 04 75 05 e8 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 5a 72 cc}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 2e 68 74 6d 74 12 3d 2e 70 68 70 74 0b 3d 2e 61 73 70 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {80 3f 2f 75 f2 80 7f 05 3e 75 ec 8b 57 01 81 e2 df df df df 81 fa 42 4f 44 59 75 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

