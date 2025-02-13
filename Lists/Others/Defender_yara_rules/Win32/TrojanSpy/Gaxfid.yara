rule TrojanSpy_Win32_Gaxfid_A_2147661393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gaxfid.A"
        threat_id = "2147661393"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gaxfid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%c:\\Program Files\\%d.%c%c%c" ascii //weight: 3
        $x_3_2 = "%c:\\Program Files\\tmp.dat" ascii //weight: 3
        $x_4_3 = "&0124fgGaxfdFdx&" ascii //weight: 4
        $x_5_4 = "%c:\\Program Files\\%d.jpg" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

