rule BrowserModifier_Win32_HMToolbar_17327_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/HMToolbar"
        threat_id = "17327"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "HMToolbar"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "TOOLBAR name=\"hmtoolbar\"" ascii //weight: 10
        $x_10_2 = {55 4e 50 4f 50 55 50 00 50 4f 50 55 50}  //weight: 10, accuracy: High
        $x_10_3 = "http://tool.world2.cn/toolbar/" ascii //weight: 10
        $x_1_4 = "osoft\\Windows\\CurrentVersion\\Runonce" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

