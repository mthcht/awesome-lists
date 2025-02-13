rule Rogue_Win32_FakeGal_162975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeGal"
        threat_id = "162975"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeGal"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Defender Warning" ascii //weight: 1
        $x_1_2 = "security_alert" ascii //weight: 1
        $x_1_3 = "AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "billing_browser" ascii //weight: 1
        $x_1_5 = "pathToSignedProductExe" ascii //weight: 1
        $x_1_6 = "can't connect to SecurityCenter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

