rule Trojan_Win64_Wikiloader_XZ_2147902787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wikiloader.XZ!MTB"
        threat_id = "2147902787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wikiloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 d9 48 c7 c0 2f 00 00 00 48 83 c0 31 65 48 8b 18 48 c7 c0 10 00 00 00 48 83 c0 08 50 48 31 c0 48 ff c0 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Wikiloader_A_2147922661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wikiloader.A!MTB"
        threat_id = "2147922661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wikiloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 5d f8 4d 31 c0 49 c7 c2 33 00 00 00 49 83 c2 09 46 8b 04 13 50 48 31 c0 48 ff c0 48 85 c0 74 78 58}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 0c 4e 48 31 f6 49 c7 c2 0d 00 00 00 49 83 c2 0f 43 8b 34 10 48 01 de 48 31 d2 52 48 31 d2 48 85 d2}  //weight: 1, accuracy: High
        $x_1_3 = "Base64 Encode" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

