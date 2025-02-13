rule TrojanSpy_Win32_QQSpyspe_A_2147693877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/QQSpyspe.A"
        threat_id = "2147693877"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "QQSpyspe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s\\~@fatHj%d.exe" ascii //weight: 3
        $x_1_2 = "%s\\DownServ" ascii //weight: 1
        $x_1_3 = "%s\\paantsh" ascii //weight: 1
        $x_1_4 = "newqqrec" ascii //weight: 1
        $x_1_5 = "dirlist monitorvalue: %s" ascii //weight: 1
        $x_1_6 = "%s@raidcall.com.tw.dat" wide //weight: 1
        $x_1_7 = "%s\\%s\\db\\msghis.imw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

