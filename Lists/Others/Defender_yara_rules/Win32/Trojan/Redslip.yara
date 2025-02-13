rule Trojan_Win32_Redslip_RPX_2147904909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redslip.RPX!MTB"
        threat_id = "2147904909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redslip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 53 f8 39 13 8b 4d e4 0f 4f 13 8d 5b 28 03 53 d4 8d 41 ff 03 c2 33 d2 f7 f1 0f af c1 3b f8 0f 4d c7 8b f8 83 ee 01 75 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

