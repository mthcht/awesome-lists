rule Trojan_Win32_Ponystealer_RC_2147898498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ponystealer.RC!MTB"
        threat_id = "2147898498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ponystealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9a 20 28 de 16 6e 32 13 01 09 28 4c c8 17 6f 75 19}  //weight: 1, accuracy: High
        $x_1_2 = "candida poofter foredoom burble prangs pleading genealog" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ponystealer_MBXS_2147919376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ponystealer.MBXS!MTB"
        threat_id = "2147919376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ponystealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 51 00 18 f9 37 01 20 ff ff ff 08 00 00 00 01 00 00 00 02 00 00 00 e9 00 00 00 60 10 51 00 d4 0e 51 00 e0 11 40 00 78 00 00 00 83 00 00 00 8d 00 00 00 8e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ponystealer_SOB_2147935951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ponystealer.SOB!MTB"
        threat_id = "2147935951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ponystealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Humiliator5" ascii //weight: 2
        $x_2_2 = "Frontalsammenstd6" ascii //weight: 2
        $x_2_3 = "Skeletterings" ascii //weight: 2
        $x_2_4 = "Tapsamlinger1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

