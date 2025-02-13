rule Backdoor_Win32_Sharat_A_2147648107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharat.gen!A"
        threat_id = "2147648107"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {25 63 00 00 25 63 00 00 25 63 00 00 30 00 00 00 30 00 00 00 77 69 6e 00}  //weight: 3, accuracy: High
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_2_3 = {2e 25 64 0a 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

