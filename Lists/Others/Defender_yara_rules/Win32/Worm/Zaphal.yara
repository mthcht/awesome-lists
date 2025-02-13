rule Worm_Win32_Zaphal_A_2147652355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zaphal.A"
        threat_id = "2147652355"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zaphal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuck" ascii //weight: 1
        $x_1_2 = "update.php?" ascii //weight: 1
        $x_1_3 = "yahoobuddymain" ascii //weight: 1
        $x_1_4 = "passwd=" ascii //weight: 1
        $x_1_5 = "&h[]=profile.zapto.org&ip=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

