rule TrojanSpy_Win32_Kolnops_A_2147692423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kolnops.A"
        threat_id = "2147692423"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolnops"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-user dumps@zerokool.cc" ascii //weight: 2
        $x_1_2 = "Raport de la %computername%" ascii //weight: 1
        $x_1_3 = "-smtp 37.59.26.94" ascii //weight: 1
        $x_1_4 = "-pass 1234qwer" ascii //weight: 1
        $x_1_5 = "-attach backup.7z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

