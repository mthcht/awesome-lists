rule Trojan_Win32_ChipLoader_RPX_2147912209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChipLoader.RPX!MTB"
        threat_id = "2147912209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChipLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 89 e2 81 c2 04 00 00 00 83 ea 04 87 14 24 5c 89 04 24 89 34 24 56 89 e6 81 c6 04 00 00 00 83 ee 04 87 34 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

