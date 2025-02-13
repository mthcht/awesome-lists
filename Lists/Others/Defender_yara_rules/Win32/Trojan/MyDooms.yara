rule Trojan_Win32_MyDooms_LKA_2147896839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MyDooms.LKA!MTB"
        threat_id = "2147896839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MyDooms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 0f 8b 13 8b 43 04 89 04 1a 83 c3 08 ff 09 eb ec}  //weight: 1, accuracy: High
        $x_1_2 = {81 2a 6a 17 62 3c eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

