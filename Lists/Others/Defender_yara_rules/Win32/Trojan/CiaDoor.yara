rule Trojan_Win32_CiaDoor_GIS_2147811650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CiaDoor.GIS!MTB"
        threat_id = "2147811650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CiaDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 e4 8b 51 14 2b c2 8b 51 10 3b c2 89 85 bc fc ff ff 72 20}  //weight: 10, accuracy: High
        $x_10_2 = {8b 41 14 8b 51 10 f7 d8 3b c2 89 85 bc fc ff ff 72 20}  //weight: 10, accuracy: High
        $x_1_3 = "del a.bat" ascii //weight: 1
        $x_1_4 = "\\temp\\melt.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

