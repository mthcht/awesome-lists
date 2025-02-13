rule Backdoor_Win32_Zewit_A_2147638342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zewit.A"
        threat_id = "2147638342"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zewit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POST /gateway/report HTTP/1.0" ascii //weight: 1
        $x_1_2 = "botver=%s&build=%s" ascii //weight: 1
        $x_1_3 = "%sRECYCLER\\autorun.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

