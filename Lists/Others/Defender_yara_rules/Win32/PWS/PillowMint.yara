rule PWS_Win32_PillowMint_A_2147769837_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PillowMint.A"
        threat_id = "2147769837"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PillowMint"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_2 = "OpenProcess" ascii //weight: 1
        $x_1_3 = "AccountingIQ.exe" ascii //weight: 1
        $x_1_4 = {c7 85 f0 02 00 00 00 00 00 00 8b 85 f0 02 00 00 48 98 48 3d 89 00 00 00 77 2d 8b 85 f0 02 00 00 48 98 0f b6 84 05 20 02 00 00 83 f0 70 89 c2 8b 85 f0 02 00 00 48 98 88 94 05 90 01 00 00 83 85 f0 02 00 00 01 eb c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

