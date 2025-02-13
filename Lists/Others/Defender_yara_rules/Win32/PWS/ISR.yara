rule PWS_Win32_ISR_GG_2147776489_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/ISR.GG!MTB"
        threat_id = "2147776489"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "ISR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?action=add&username=" ascii //weight: 1
        $x_1_2 = "jDownloader" ascii //weight: 1
        $x_1_3 = "&password=" ascii //weight: 1
        $x_1_4 = "&app=" ascii //weight: 1
        $x_1_5 = "&pcname=" ascii //weight: 1
        $x_1_6 = "&sitename=" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
        $x_1_8 = "<Server>" ascii //weight: 1
        $x_1_9 = "<Pass>" ascii //weight: 1
        $x_1_10 = "InjPE" ascii //weight: 1
        $x_1_11 = "EncPassword" ascii //weight: 1
        $x_1_12 = "Trillian" ascii //weight: 1
        $x_1_13 = "\\.purple\\accounts.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

