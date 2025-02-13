rule TrojanDropper_Win32_Lisiu_A_2147630965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lisiu.A"
        threat_id = "2147630965"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisiu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 4c 24 14 6a 00 51 8d 54 24 1b 8b f0 6a 01 52 56 c6 44 24 27 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

