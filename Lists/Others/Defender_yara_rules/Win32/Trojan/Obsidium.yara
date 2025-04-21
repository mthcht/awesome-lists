rule Trojan_Win32_Obsidium_AMMF_2147906576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obsidium.AMMF!MTB"
        threat_id = "2147906576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obsidium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 5a c2 00 ba 11 a9 fe 2b 47 e9 8e d5 86 64 33 18 91 52 44 6a 52 dd 86 92 8a 8a 49 d7 a2 92 74 80 ba 34 25 b4 21 5a fb 12 d3 ea 56 09 64 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obsidium_A_2147939482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obsidium.A!MTB"
        threat_id = "2147939482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obsidium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 dc 71 5b eb 03 d2 a5 00 eb 05 32 ae 3f 9b 0a b8 0e 48 3c f7 eb 01 76 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

