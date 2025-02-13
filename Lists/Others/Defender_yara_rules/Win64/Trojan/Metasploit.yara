rule Trojan_Win64_Metasploit_CRTD_2147850034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Metasploit.CRTD!MTB"
        threat_id = "2147850034"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 28 49 c7 c1 40 00 00 00 49 c7 c0 00 30 00 00 48 c7 c2 00 10 00 00 48 33 c9 e8 27 10 00 00 48 c7 c1 00 10 00 00 48 be 41 10 00 40 01 00 00 00 48 8b f8 f3 a4 ff d0 48 33 c9 e8 01 10 00 00 50 41 59 4c 4f 41 44 3a 00}  //weight: 1, accuracy: High
        $x_1_2 = "PAYLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Metasploit_AMBC_2147903241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Metasploit.AMBC!MTB"
        threat_id = "2147903241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 10 44 31 c0 89 c1 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 83 45 fc 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

