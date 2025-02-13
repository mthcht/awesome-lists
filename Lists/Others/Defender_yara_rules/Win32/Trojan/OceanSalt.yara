rule Trojan_Win32_OceanSalt_GDA_2147839867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OceanSalt.GDA!MTB"
        threat_id = "2147839867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OceanSalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 00 20 41 00 80 30 0f 40 3d 56 4e 41 00 7e f5}  //weight: 10, accuracy: High
        $x_1_2 = "27.102.112.179" ascii //weight: 1
        $x_1_3 = "\\Public\\Videos\\temp.log" ascii //weight: 1
        $x_1_4 = "SRQharyAhLibrhLoadTS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

