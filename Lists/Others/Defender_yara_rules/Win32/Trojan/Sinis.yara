rule Trojan_Win32_Sinis_C_2147646506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sinis.C"
        threat_id = "2147646506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 2
        $x_2_2 = "\\md5dll.dll" ascii //weight: 2
        $x_1_3 = "cryo-update.ca/" ascii //weight: 1
        $x_1_4 = "startaliance.info/" ascii //weight: 1
        $x_1_5 = "driverupdservers.net/" ascii //weight: 1
        $x_1_6 = "/cfg/upd.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

