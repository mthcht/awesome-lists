rule Backdoor_Win32_Faketask_C_2147727832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Faketask.C"
        threat_id = "2147727832"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Faketask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VACqItywGR1v3qGxVZQPYXxMZV0o2fzp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

