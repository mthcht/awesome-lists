rule Backdoor_Win32_Wudfok_A_2147640852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wudfok.A"
        threat_id = "2147640852"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wudfok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WinXS 2.0 demon" ascii //weight: 3
        $x_3_2 = "\\WudfSvc.exe" ascii //weight: 3
        $x_2_3 = "%s %s HTTP/%d.%d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

