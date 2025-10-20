rule Trojan_Win32_SusValakSchtasks_MK_2147955533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusValakSchtasks.MK"
        threat_id = "2147955533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusValakSchtasks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /Create " ascii //weight: 1
        $x_1_2 = "/F /TN " ascii //weight: 1
        $x_1_3 = " /TR \"WSCRIPT.exe //E:jscript " ascii //weight: 1
        $x_1_4 = "\"Classic Sound\"" ascii //weight: 1
        $x_1_5 = ".bz:Default2.ini" ascii //weight: 1
        $x_1_6 = "/SC Minute /MO " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

