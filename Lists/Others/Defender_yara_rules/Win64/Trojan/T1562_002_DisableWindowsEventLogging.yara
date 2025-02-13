rule Trojan_Win64_T1562_002_DisableWindowsEventLogging_A_2147846080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1562_002_DisableWindowsEventLogging.A"
        threat_id = "2147846080"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1562_002_DisableWindowsEventLogging"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "event::drop" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

