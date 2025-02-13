rule Worm_Win32_Soltern_GMH_2147889371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Soltern.GMH!MTB"
        threat_id = "2147889371"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Soltern"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dUKSqJnb" ascii //weight: 1
        $x_1_2 = "NUdqtLqT" ascii //weight: 1
        $x_10_3 = {45 f0 e8 49 e4 ff ff c3 e9 67 70 ff ff eb f0 8b d6 8b c3 8b cf e8 02 fd ff ff 5f 5e 5b 8b e5 5d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

