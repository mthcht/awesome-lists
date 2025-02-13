rule Trojan_Win32_Badappx_A_2147755654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Badappx.A"
        threat_id = "2147755654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Badappx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "wsu*.tmp" ascii //weight: 100
        $x_100_2 = "PlaceholderTileLogoFolder" ascii //weight: 100
        $x_20_3 = "\\??\\c:" wide //weight: 20
        $x_20_4 = "\\??\\d:" wide //weight: 20
        $x_20_5 = "\\??\\e:" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

