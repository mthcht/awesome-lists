rule Trojan_Win32_Uascape_A_2147708128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uascape.A"
        threat_id = "2147708128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uascape"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConsentPromptBehaviorAdmin" ascii //weight: 1
        $x_1_2 = "HideSCAHealth" ascii //weight: 1
        $x_1_3 = "LowRiskFileTypes" ascii //weight: 1
        $x_10_4 = "$$\\wininit.ini" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

