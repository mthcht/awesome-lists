rule Trojan_Win32_LambLoad_B_2147896170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LambLoad.B!dha"
        threat_id = "2147896170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LambLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {80 34 32 59 4a 79 e3 80 3e 4d 75 12 80 7e 01 5a 75 0c}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

