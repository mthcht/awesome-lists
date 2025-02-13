rule Ransom_Win32_NefiCrypt_PA_2147759765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NefiCrypt.PA!MTB"
        threat_id = "2147759765"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NefiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Go build ID: \"BfUvnTM6FFYH3WSvi0DS/mGO2ay6vyoGkFwdwQaTD/exXn-FZ3HzR2jVTpiLBu/34lCPROA9vh2AZkZbgCU" ascii //weight: 5
        $x_1_2 = "\\README.html_" ascii //weight: 1
        $x_1_3 = "don't rename your file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

