rule Trojan_Win32_Hidrun_A_2147625067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hidrun.A"
        threat_id = "2147625067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hidrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 f7 db eb ?? 0f be 46 01 46 50 e8 ?? ?? ?? ?? 8b d8 c1 e3 04 46 46 0f be 06 50 46}  //weight: 10, accuracy: Low
        $x_5_2 = "ie_hide_run" ascii //weight: 5
        $x_1_3 = "Downloaded Program Files\\floders.ini" ascii //weight: 1
        $x_1_4 = "557b9038-fc87-453c-8b08-32d85f46eac4" ascii //weight: 1
        $x_1_5 = "search.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

