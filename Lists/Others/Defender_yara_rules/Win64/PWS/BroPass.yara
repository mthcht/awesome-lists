rule PWS_Win64_BroPass_CA_2147970032_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/BroPass.CA!MTB"
        threat_id = "2147970032"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "BroPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 8a 04 02 48 ff c7 32 44 0d ?? 48 ff c1 88 02 48 ff c2 49 3b cc 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {30 03 48 ff c3 48 83 ee 01 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

