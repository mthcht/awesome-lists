rule Trojan_Win32_Redenav_2147615122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redenav"
        threat_id = "2147615122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redenav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 61 76 65 72 2e 63 6f 6d 00}  //weight: 2, accuracy: High
        $x_2_2 = "com/ovn_click.asp" ascii //weight: 2
        $x_1_3 = "com/exe/dname.html" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-2] 6f 6c 62 61 72 32 62}  //weight: 1, accuracy: Low
        $x_1_5 = "reward/reward.asp?mode" ascii //weight: 1
        $x_1_6 = "Software\\guidetoolbar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

