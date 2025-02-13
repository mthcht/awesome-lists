rule Trojan_Win32_WarzoneRAT_DG_2147917642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WarzoneRAT.DG!MTB"
        threat_id = "2147917642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WarzoneRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "$cc7fad03-816e-432c-9b92-001f2d378494" ascii //weight: 50
        $x_5_2 = "Base64String" ascii //weight: 5
        $x_5_3 = "CreateInstance" ascii //weight: 5
        $x_5_4 = "Invoke" ascii //weight: 5
        $x_1_5 = "get_encrypted" ascii //weight: 1
        $x_1_6 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

