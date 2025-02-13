rule Trojan_Win64_T1115_ClipboardData_A_2147846088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1115_ClipboardData.A"
        threat_id = "2147846088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1115_ClipboardData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "misc::clip" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

