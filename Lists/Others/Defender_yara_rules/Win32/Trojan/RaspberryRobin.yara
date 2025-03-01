rule Trojan_Win32_RaspberryRobin_ARR_2147898847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaspberryRobin.ARR!MTB"
        threat_id = "2147898847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaspberryRobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 11 c7 41 10 f7 06 00 00 c7 41 0c f7 06 00 00 c7 41 08 f7 06 00 00 c7 41 04 f7 06 00 00 8b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

