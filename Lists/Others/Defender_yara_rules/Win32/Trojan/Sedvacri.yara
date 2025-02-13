rule Trojan_Win32_Sedvacri_A_2147707815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sedvacri.A"
        threat_id = "2147707815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sedvacri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hackerci|" ascii //weight: 1
        $x_1_2 = "sendvcode/myapi/" ascii //weight: 1
        $x_1_3 = "API_FindPassword" ascii //weight: 1
        $x_1_4 = "<span style=\\\"line-height: 28px;\\\"   \\>" ascii //weight: 1
        $x_1_5 = "del C:\\123.bat" ascii //weight: 1
        $x_1_6 = "\\dm.dll /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

