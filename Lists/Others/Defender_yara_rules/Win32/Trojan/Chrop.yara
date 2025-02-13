rule Trojan_Win32_Chrop_DF_2147798521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chrop.DF!MTB"
        threat_id = "2147798521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 83 ec 08 6a 03}  //weight: 10, accuracy: High
        $x_3_2 = "SetSecurityDescriptorDacl" ascii //weight: 3
        $x_3_3 = "DllInstall" ascii //weight: 3
        $x_3_4 = "Software GmbH" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

