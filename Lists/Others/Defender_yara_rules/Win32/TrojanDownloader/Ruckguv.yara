rule TrojanDownloader_Win32_Ruckguv_A_2147693047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ruckguv.A"
        threat_id = "2147693047"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruckguv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {c6 00 68 89 48 01 c6 40 05 c3}  //weight: 1, accuracy: High
        $x_1_3 = "%s\\WindowsDriver_%d.exe" ascii //weight: 1
        $x_1_4 = "uggc://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

