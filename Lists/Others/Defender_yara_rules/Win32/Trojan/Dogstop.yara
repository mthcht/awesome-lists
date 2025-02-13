rule Trojan_Win32_Dogstop_A_2147639279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogstop.A"
        threat_id = "2147639279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogstop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spyroZONE\\KK9" wide //weight: 1
        $x_1_2 = "SPYRO KiD will send another lion for you" wide //weight: 1
        $x_1_3 = "Bypass K9 Web Protection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

