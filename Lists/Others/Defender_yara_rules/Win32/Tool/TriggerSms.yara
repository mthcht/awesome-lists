rule Tool_Win32_TriggerSms_A_284766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tool:Win32/TriggerSms.A"
        threat_id = "284766"
        type = "Tool"
        platform = "Win32: Windows 32-bit platform"
        family = "TriggerSms"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "88793906-c2eb-42f1-9f13-f922fb454e23" wide //weight: 10
        $x_10_2 = "d0027073-ea64-42ca-8293-241186e9011f" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

