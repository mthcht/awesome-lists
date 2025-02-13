rule TrojanSpy_Win32_Sercofy_A_2147633504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sercofy.A"
        threat_id = "2147633504"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sercofy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Are you user?" ascii //weight: 1
        $x_1_2 = "Cannot find directory with write\\read rights." ascii //weight: 1
        $x_1_3 = "Close antivirus\\firewall." ascii //weight: 1
        $x_1_4 = "\\bu-bu.exe" ascii //weight: 1
        $x_1_5 = "fails. GetLastError = %X." ascii //weight: 1
        $x_1_6 = "_TID+delta] <> 0." ascii //weight: 1
        $x_1_7 = "%us:PID:%d:TID:%d:%p2d.%p2d.%p2d.%p2d::%s" ascii //weight: 1
        $x_1_8 = "%s\\%p4d.%p2d.%p2d.%p2d.%p2d.%p2d.%p3d.txt" ascii //weight: 1
        $x_1_9 = "/modules/Files/pub_dir/sery/sery%d.exe" ascii //weight: 1
        $x_1_10 = "Global\\SATASERY_RM" ascii //weight: 1
        $x_1_11 = "OS info:[dwMajorVersion]=%X,[dwMinorVersion]=%X,[dwBuildNumber]=%X" ascii //weight: 1
        $x_1_12 = "%s\\Screenshots\\" ascii //weight: 1
        $x_1_13 = "SERYLOGIN@mail.ru" ascii //weight: 1
        $x_3_14 = {f7 d9 8d 56 05 2b 55 0c 39 d1 76 03 01 7e 01 eb 19 83 f8 06 75 14 80 3e ff 75 0f 80 7e 01 90 72 09 80 7e 01 97 77 03 01 7e 02 01 c6 eb a0}  //weight: 3, accuracy: High
        $x_3_15 = {c7 04 24 00 00 00 00 8a 06 84 c0 0f 84 b0 00 00 00 3c 25 74 03 a4 eb e8 8a 46 01 3c 64 74 5d}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

