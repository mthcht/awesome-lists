rule Worm_Win32_YahLover_A_2147582959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/YahLover.A"
        threat_id = "2147582959"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "YahLover"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/update.txt" wide //weight: 1
        $x_1_2 = "Explorer\\Control Panel" wide //weight: 1
        $x_1_3 = "CurrentVersion\\Policies\\System" wide //weight: 1
        $x_2_4 = "DisableRegistryTools" wide //weight: 2
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_6 = "Start Page" wide //weight: 1
        $x_2_7 = "pager\\View\\YMSGR" wide //weight: 2
        $x_2_8 = "taskkill /im a" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

