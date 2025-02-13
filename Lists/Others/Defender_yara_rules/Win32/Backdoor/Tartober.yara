rule Backdoor_Win32_Tartober_A_2147679422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tartober.A"
        threat_id = "2147679422"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tartober"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VRLDownloadToCacheFileA" ascii //weight: 1
        $x_1_2 = "Hello@)!0" ascii //weight: 1
        $x_1_3 = "!(*@)(!@URL" ascii //weight: 1
        $x_1_4 = "?%d-%d-%d=" ascii //weight: 1
        $x_1_5 = "\\~hf~\\" ascii //weight: 1
        $x_1_6 = "\\AdobeRe.exe" ascii //weight: 1
        $x_1_7 = "dmd /c" ascii //weight: 1
        $x_1_8 = "Ttartup Toftware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

