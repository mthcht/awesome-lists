rule TrojanClicker_Win32_Yinsuide_A_2147717359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Yinsuide.A"
        threat_id = "2147717359"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Yinsuide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ctrl.shuidun.org/cfg.txt" wide //weight: 1
        $x_1_2 = "/tn \"YRTestTask\" /tr" wide //weight: 1
        $x_1_3 = "\\users\\yr.net\\desktop\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

