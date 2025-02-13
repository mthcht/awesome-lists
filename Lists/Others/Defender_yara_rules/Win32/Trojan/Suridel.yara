rule Trojan_Win32_Suridel_A_2147655174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suridel.A"
        threat_id = "2147655174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suridel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copy_virus_cache" ascii //weight: 1
        $x_1_2 = "zamena_fail" ascii //weight: 1
        $x_1_3 = "kick_antivirus" ascii //weight: 1
        $x_1_4 = "#VIRUS 2005\\virus rundll32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

