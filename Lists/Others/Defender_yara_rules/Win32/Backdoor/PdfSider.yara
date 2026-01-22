rule Backdoor_Win32_PdfSider_C_2147961600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PdfSider.C!MTB"
        threat_id = "2147961600"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PdfSider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "COMPUTERNAME" ascii //weight: 2
        $x_2_2 = "USERNAME" ascii //weight: 2
        $x_2_3 = "logger with name 'console' already exists" ascii //weight: 2
        $x_2_4 = "aes_decrypt" ascii //weight: 2
        $x_2_5 = "{\"name\": \"%s\", \"build_date\": \"%s %s\", \"arch\": \"windows\", \"username\": \"%s\", \"pid\": \"%d\" }" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

