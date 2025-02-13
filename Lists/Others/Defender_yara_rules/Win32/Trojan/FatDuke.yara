rule Trojan_Win32_FatDuke_A_2147752030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatDuke.A!dha"
        threat_id = "2147752030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatDuke"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploading_data" ascii //weight: 1
        $x_1_2 = "received_data" ascii //weight: 1
        $x_1_3 = "%H : %M : S" ascii //weight: 1
        $x_1_4 = "%d / %m / %y" ascii //weight: 1
        $x_10_5 = "81fcb4eaf5fa4f21842057b505dc07c4.dll" ascii //weight: 10
        $x_10_6 = "11.00.9600.18098" ascii //weight: 10
        $x_10_7 = "CategoryIDs contains '0761a70a-00ec-4245-bf3a-aa4fdb14609d'" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

