rule Spammer_Win32_Baxin_2147627340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Baxin"
        threat_id = "2147627340"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Baxin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<communications_msn_cs_ptbr@microsoft.windowslive.com>" wide //weight: 1
        $x_1_2 = "tudo\\baixa darlam\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

