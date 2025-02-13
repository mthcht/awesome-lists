rule Trojan_Win32_Vareids_A_2147628230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vareids.A"
        threat_id = "2147628230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vareids"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 89 50 02 c7 40 04 7f 00 00 01}  //weight: 2, accuracy: High
        $x_1_2 = "msvpx86.aqmgu" ascii //weight: 1
        $x_1_3 = "msvkx86.aqmgu" ascii //weight: 1
        $x_1_4 = "HARDVARE_ID%" ascii //weight: 1
        $x_1_5 = "SETTINGS_ADLER%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

