rule Worm_Win32_MyDoom_EM_2147896860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/MyDoom.EM!MTB"
        threat_id = "2147896860"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "MyDoom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "devil2100" ascii //weight: 1
        $x_1_2 = "shaib200" ascii //weight: 1
        $x_1_3 = "alma7roomm" ascii //weight: 1
        $x_1_4 = "jasim810" ascii //weight: 1
        $x_1_5 = "warrer_50" ascii //weight: 1
        $x_1_6 = "mohammed007" ascii //weight: 1
        $x_1_7 = "rah.polaka" ascii //weight: 1
        $x_1_8 = "sskeralexander" ascii //weight: 1
        $x_1_9 = "ambatukam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

