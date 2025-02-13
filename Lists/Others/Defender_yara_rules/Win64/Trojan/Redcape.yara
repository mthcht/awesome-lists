rule Trojan_Win64_Redcape_RPX_2147851896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcape.RPX!MTB"
        threat_id = "2147851896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f d5 f7 41 5f 41 55 66 41 bd 03 00 41 50 45 01 c5 0f 77 41 58 0f f5 eb 41 5d 48 83 34 c1 77 52 48 c7 c2 03 00 00 00 41 53 41 50 41 58 41 5b 48 ff ca 75 f3 5a 48 ff c0 48 83 f8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcape_RPY_2147851897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcape.RPY!MTB"
        threat_id = "2147851897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 5e 0f 73 d4 0e 0f de e5 41 5d 80 34 01 75 53 90 0f 77 41 50 0f ea c8 41 58 48 ff c3 66 83 eb 02 5b 48 ff c0 48 83 f8 04 75 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

