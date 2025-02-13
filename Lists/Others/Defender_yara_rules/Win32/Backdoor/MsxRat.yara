rule Backdoor_Win32_MsxRat_2147690852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/MsxRat!dha"
        threat_id = "2147690852"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "MsxRat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MsxStduOneStart.com" ascii //weight: 1
        $x_2_2 = "msxRAT1.0" ascii //weight: 2
        $x_1_3 = "msx.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

