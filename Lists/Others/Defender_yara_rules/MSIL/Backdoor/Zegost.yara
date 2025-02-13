rule Backdoor_MSIL_Zegost_GG_2147782760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Zegost.GG!MTB"
        threat_id = "2147782760"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "svp7." ascii //weight: 10
        $x_10_2 = "%s\\admin$\\hackshen.exe" ascii //weight: 10
        $x_1_3 = "VMware" ascii //weight: 1
        $x_1_4 = "[CLEAR]" ascii //weight: 1
        $x_1_5 = "[Print Screen]" ascii //weight: 1
        $x_1_6 = "angel" ascii //weight: 1
        $x_1_7 = "xpuser" ascii //weight: 1
        $x_1_8 = "McAfee" ascii //weight: 1
        $x_1_9 = "BitDefender" ascii //weight: 1
        $x_1_10 = "password" ascii //weight: 1
        $x_1_11 = "\\\\.\\PHYSICALDRIVE0" ascii //weight: 1
        $x_1_12 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

