rule Trojan_Win32_OyesterLoader_YR_2147913258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OyesterLoader.YR!MTB"
        threat_id = "2147913258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 68 70 f5 32 10 6a 01 6a 00 ff 15 d8 c0 29 10}  //weight: 1, accuracy: High
        $x_1_2 = "postman\\Desktop\\NZT\\ProjectD_cpprest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OyesterLoader_WQF_2147919395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OyesterLoader.WQF!MTB"
        threat_id = "2147919395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 53 6a 01 89 87 24 03 00 00 88 9f 2c 03 00 00 89 9f 30 03 00 00 89 9f 28 03 00 00 89 b7 34 03 00 00 83 4e 0c ff 53 ff 15 44 f0 08 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

