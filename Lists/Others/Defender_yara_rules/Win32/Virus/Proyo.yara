rule Virus_Win32_Proyo_2147597741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Proyo"
        threat_id = "2147597741"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Proyo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "333"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "{4D36E967-E325-11CE-BFC1-08002BE10318}" ascii //weight: 100
        $x_100_3 = "cmd.exe /c explorer" ascii //weight: 100
        $x_10_4 = "\\oyo.exe" ascii //weight: 10
        $x_10_5 = "\\autorun.inf" ascii //weight: 10
        $x_10_6 = "Explorer.EXE" ascii //weight: 10
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "avp.exe" ascii //weight: 1
        $x_1_10 = "360tray.exe" ascii //weight: 1
        $x_1_11 = "IceSword.exe" ascii //weight: 1
        $x_1_12 = "RavMon.exe" ascii //weight: 1
        $x_1_13 = "nod32.exe" ascii //weight: 1
        $x_1_14 = "nod32krn.exe" ascii //weight: 1
        $x_1_15 = "nod32kui.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

