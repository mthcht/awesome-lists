rule Trojan_Win32_InvisiMole_EC_2147814210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InvisiMole.EC!MTB"
        threat_id = "2147814210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InvisiMole"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 08 8b f1 c1 ee 1e 33 f1 69 f6 65 89 07 6c 03 f2 89 70 04 83 c0 04 42}  //weight: 5, accuracy: High
        $x_5_2 = {f7 d8 1b c0 25 00 00 00 02 50 6a 03 6a 00 6a 01 68 00 01 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

