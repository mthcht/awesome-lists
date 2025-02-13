rule BrowserModifier_Win32_Xiazai_223573_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Xiazai"
        threat_id = "223573"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Xiazai"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/down.xiazai" ascii //weight: 10
        $x_1_2 = "SetShortCutArgs" ascii //weight: 1
        $x_1_3 = "Software\\Policies\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_4 = "$\\wininit.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

