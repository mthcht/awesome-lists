rule Backdoor_Win32_DCRAT_JP_2147826417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DCRAT.JP!MTB"
        threat_id = "2147826417"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DCRat.Code" wide //weight: 1
        $x_1_2 = "Processing stealer plugins" wide //weight: 1
        $x_1_3 = "stealerlogstatus" wide //weight: 1
        $x_1_4 = "aHR0cHM6Ly9pcGluZm8uaW8vanNvbg" wide //weight: 1
        $x_1_5 = "H4sIAAAAAAAEA" wide //weight: 1
        $x_1_6 = "ICBfX18gICAgICAgICAgIF8gICAgICBfX18gICAgICAgICAgICAgX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

