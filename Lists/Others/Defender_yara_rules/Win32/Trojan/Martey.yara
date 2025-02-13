rule Trojan_Win32_Martey_RPX_2147900471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Martey.RPX!MTB"
        threat_id = "2147900471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Martey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 55 8d 44 24 1c 50 ff 74 24 28 ff d3 6a 15 58 66 89 44 24 14 66 89 44 24 16 8d 84 24 94 00 00 00 89 44 24 18 8d 84 24 b8 00 00 00 50 55 8d 44 24 1c 50 ff 74 24 28 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

