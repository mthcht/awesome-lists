rule Trojan_Win64_RedLineStealer_SPIZ_2147928400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedLineStealer.SPIZ!MTB"
        threat_id = "2147928400"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GqgWzd" ascii //weight: 2
        $x_2_2 = "worker_FDhvwc" ascii //weight: 2
        $x_1_3 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_4 = "procexp.exe" ascii //weight: 1
        $x_1_5 = "x64dbg.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

