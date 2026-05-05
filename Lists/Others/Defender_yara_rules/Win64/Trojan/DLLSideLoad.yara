rule Trojan_Win64_DLLSideLoad_MKR_2147968420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.MKR!MTB"
        threat_id = "2147968420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 31 34 5a 0f b6 c0 66 89 04 4a 41 3b 4c 24 10 7c}  //weight: 5, accuracy: High
        $x_1_2 = "autorun.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

