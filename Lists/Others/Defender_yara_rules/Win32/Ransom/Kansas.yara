rule Ransom_Win32_Kansas_YDQ_2147974867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kansas.YDQ!MTB"
        threat_id = "2147974867"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kansas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "kansas4life" ascii //weight: 5
        $x_5_2 = "decrypt and restore" ascii //weight: 5
        $x_5_3 = "RANSOMWARE COMPLETED SUCCESSFULLY!" ascii //weight: 5
        $x_5_4 = "C:\\ProgramData\\KANSASGROUP.txt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

