rule Trojan_Win32_LambRing_A_2147957198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LambRing.A!dha"
        threat_id = "2147957198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LambRing"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6f 63 78 78 6c 73 78 6c 73 ?? 70 70 74 70 70 74 78 70 64 66 74 78 74 64 6f 63}  //weight: 1, accuracy: Low
        $x_1_2 = {56 1a 19 07 1d 16 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

