rule Trojan_Win32_Sfloost_A_2147710757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfloost.A!bit"
        threat_id = "2147710757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfloost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1e 2a d1 02 d3 80 ea ?? 46 88 ?? ?? ?? ?? ?? 40 4f 75 e6}  //weight: 2, accuracy: Low
        $x_1_2 = "IptabLex Services" ascii //weight: 1
        $x_1_3 = "Global\\hbllxxxxServer" ascii //weight: 1
        $x_1_4 = "Global\\hbllxxxxClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

