rule Worm_Win32_Shoder_YBM_2147969112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Shoder.YBM!MTB"
        threat_id = "2147969112"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Shoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck you president of USA" ascii //weight: 1
        $x_1_2 = "bush the son" ascii //weight: 1
        $x_1_3 = "America is not a free world" ascii //weight: 1
        $x_1_4 = "Iraq and what" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

