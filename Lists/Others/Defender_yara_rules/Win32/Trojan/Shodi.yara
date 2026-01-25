rule Trojan_Win32_Shodi_YBG_2147961688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shodi.YBG!MTB"
        threat_id = "2147961688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shodi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 59 e8 90 ff ff ff 83 f8 01 0f 8e be 00 00 00 56 59 e8 96 ff ff ff 83 f8 05 0f 84 90 00 00 00 56 59 e8 44 ff ff ff 83 f8 06 75 0c 56 59 e8 64 ff ff ff 83 f8 0a 74}  //weight: 1, accuracy: High
        $x_1_2 = "UsaShohdi" ascii //weight: 1
        $x_1_3 = "Even America is not a free world" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

