rule Backdoor_Win32_Miki_2147723610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Miki"
        threat_id = "2147723610"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Miki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JgAoACAAJABzAGgARQBMAEwASQBEAFsAMQBdACsAJABzAEgARQBsAEwASQBkAFsAMQAzAF0AK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

