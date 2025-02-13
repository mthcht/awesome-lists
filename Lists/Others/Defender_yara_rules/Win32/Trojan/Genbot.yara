rule Trojan_Win32_Genbot_RPX_2147888149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genbot.RPX!MTB"
        threat_id = "2147888149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 0c 8b f4 8d 45 f4 50 6a 00 6a 00 8b 4d dc 51 6a 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b f4 6a 40 68 00 10 00 00 8b 45 0c 50 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

