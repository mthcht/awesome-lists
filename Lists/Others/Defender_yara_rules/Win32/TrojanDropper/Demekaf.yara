rule TrojanDropper_Win32_Demekaf_A_2147633499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Demekaf.A"
        threat_id = "2147633499"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Demekaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3f 7a 75 09 80 7f 01 5a 75 03 c6 07 4d}  //weight: 1, accuracy: High
        $x_1_2 = {b9 2b 02 00 00 33 c0 8d 7c 24 ?? f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

