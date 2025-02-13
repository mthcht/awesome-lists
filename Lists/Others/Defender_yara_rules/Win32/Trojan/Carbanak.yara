rule Trojan_Win32_Carbanak_RPX_2147908629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carbanak.RPX!MTB"
        threat_id = "2147908629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carbanak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 45 f8 3b c3 7d 04 2b d3 03 c2 8b 5d e4 8b 55 f4 88 04 1f 8b 45 f0 47 4a 89 55 f4 46 3b f8 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Carbanak_RPY_2147908630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carbanak.RPY!MTB"
        threat_id = "2147908630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carbanak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 83 c8 01 0f af c7 29 c1 89 c8 99 f7 7d e4 89 d7 8b 75 ec 8b 55 f0 8a 04 16 8a 4d e3 d2 e0 8a 0c 3e 88 0c 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

