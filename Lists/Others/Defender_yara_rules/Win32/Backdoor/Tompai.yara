rule Backdoor_Win32_Tompai_GTN_2147927313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tompai.GTN!MTB"
        threat_id = "2147927313"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tompai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KLprojMain.exe" ascii //weight: 1
        $x_1_2 = "adj_fptan" ascii //weight: 1
        $x_1_3 = "EVENT_SINK_*" ascii //weight: 1
        $x_1_4 = "DllFQAmkp" ascii //weight: 1
        $x_1_5 = "XlOGtGU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

