rule Trojan_Win32_Roopy_LK_2147847070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Roopy.LK!MTB"
        threat_id = "2147847070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Roopy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 31 4f 81 c1 04 00 00 00 39 c1 75 ee 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

