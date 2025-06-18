rule Trojan_Win32_Trickler_ARA_2147944004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickler.ARA!MTB"
        threat_id = "2147944004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 8a 4c 95 42 00 8a c1 24 80 d0 e1 3a c3 74 03 80 c9 01 8a 82 4d 95 42 00 32 c1 8a c8 80 e1 01 d0 e8 3a cb 74 02 0c 80 88 82 4c 95 42 00 42 83 fa 03 7c cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

