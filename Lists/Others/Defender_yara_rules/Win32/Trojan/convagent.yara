rule Trojan_Win32_convagent_RPU_2147835868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/convagent.RPU!MTB"
        threat_id = "2147835868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 34 24 5b 50 89 14 24 89 2c 24 89 e5 81 c5 04 00 00 00 83 c5 04 87 2c 24 5c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 14 24 50 89 2c 24 89 1c 24 54 5b 81 c3 04 00 00 00 83 c3 04 87 1c 24 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

