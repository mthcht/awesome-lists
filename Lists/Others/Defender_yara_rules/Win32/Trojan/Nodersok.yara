rule Trojan_Win32_Nodersok_B_2147743058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nodersok.B"
        threat_id = "2147743058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nodersok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "-enc" wide //weight: 10
        $x_10_3 = "lgaoaciaewawah0aewaxah0aigagac0azganagkajwasaccazqb4accakqagacqa" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

