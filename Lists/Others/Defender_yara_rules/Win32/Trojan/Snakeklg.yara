rule Trojan_Win32_Snakeklg_GB_2147776491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snakeklg.GB!MTB"
        threat_id = "2147776491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snakeklg"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SNAKE-KEYLOGGER" ascii //weight: 10
        $x_1_2 = "S--------N--------A--------K--------E" ascii //weight: 1
        $x_1_3 = {4b 00 45 00 59 00 4c 00 4f 00 47 00 47 00 45 00 52 00 [0-30] 53 00 [0-25] 4e 00 [0-25] 41 00 [0-25] 4b 00 [0-25] 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4b 45 59 4c 4f 47 47 45 52 [0-30] 53 [0-25] 4e [0-25] 41 [0-25] 4b [0-25] 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

