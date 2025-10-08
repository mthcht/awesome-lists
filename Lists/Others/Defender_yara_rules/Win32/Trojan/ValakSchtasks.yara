rule Trojan_Win32_ValakSchtasks_MK_2147954068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValakSchtasks.MK"
        threat_id = "2147954068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValakSchtasks"
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
        $n_1_7 = "a453e881-26a8-4973-ba2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

