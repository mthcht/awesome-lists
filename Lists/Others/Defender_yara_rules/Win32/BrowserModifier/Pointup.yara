rule BrowserModifier_Win32_Pointup_136547_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Pointup"
        threat_id = "136547"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Pointup"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "reward.point-up.kr/" ascii //weight: 2
        $x_2_2 = {70 6f 69 6e 74 70 6f 69 6e 74 70 6f 69 6e 74 00}  //weight: 2, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_4 = "_IEBrowserHelper.pas" ascii //weight: 1
        $x_1_5 = "goodmoringhaha" ascii //weight: 1
        $x_1_6 = "/ilikeclick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

