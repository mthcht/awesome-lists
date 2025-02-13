rule Trojan_Win32_Stantinko_RO_2147909178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stantinko.RO!MTB"
        threat_id = "2147909178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stantinko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 04 2b 0e b8 ab aa aa 2a f7 e9 8b 06 c1 fa 02 8b fa c1 ef 1f 83 c4 20 03 fa 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stantinko_MBQ_2147932785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stantinko.MBQ!MTB"
        threat_id = "2147932785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stantinko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 65 73 74 4c 65 61 6e 49 6e 64 75 6c 67 65 6e 63 65 00 64 6c 63 6c 6f 73 65 5f 32 30 34 39 32 33 61 00 64 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

