rule Trojan_Win32_ExecutionFromADS_B_2147940641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ExecutionFromADS.B"
        threat_id = "2147940641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ExecutionFromADS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& powershell.exe - <" ascii //weight: 1
        $x_1_2 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-144] 74 00 78 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 74 65 6d 70 5c [0-144] 74 78 74 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

