rule Trojan_Win32_NoonAgent_MBXR_2147918936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NoonAgent.MBXR!MTB"
        threat_id = "2147918936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NoonAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {4d 40 00 04 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 14 4b 40 00 44 48 40 00 4c 29 40 00 78}  //weight: 3, accuracy: High
        $x_2_2 = "FILE FOLDER" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

