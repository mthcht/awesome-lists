rule TrojanDropper_Win32_Futdru_A_2147609304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Futdru.A"
        threat_id = "2147609304"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Futdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ab 8d 45 d0 33 ff 2b c8 8d 44 3d d0 8a 14 01 80 f2 af 47 83 ff 09 88 10 7c ee}  //weight: 1, accuracy: High
        $x_1_2 = {11 83 c4 1c 81 c7 ?? ?? 00 00 b9 99 00 00 00 6a 04 80 77 03 19 58 3b cb 75 0d 8a 0c 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

