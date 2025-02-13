rule Worm_Win32_Failnum_B_2147693206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Failnum.B"
        threat_id = "2147693206"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Failnum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fucking fail 3" ascii //weight: 1
        $x_1_2 = "BawtBot ;--p" ascii //weight: 1
        $x_1_3 = {ff ff de c0 ad d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

