rule Trojan_Win32_Delfiles_Q_2147639016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfiles.Q"
        threat_id = "2147639016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "del C:\\*.*/f/s/q" ascii //weight: 3
        $x_2_2 = "shutdown -r -t 600 -c \"Opfer\"" ascii //weight: 2
        $x_2_3 = "Stuxnet Cleaner.bat" ascii //weight: 2
        $x_1_4 = "assoc ." ascii //weight: 1
        $x_1_5 = "taskkill /f /t /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

