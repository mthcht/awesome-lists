rule Trojan_Win64_PasswordStealer_AMQ_2147793333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PasswordStealer.AMQ!MTB"
        threat_id = "2147793333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 d0 4c 63 c0 4e 0f b6 04 01 41 80 f0 ab 44 88 84 14 af 01 00 00 83 c0 01 83 f8 0c 75 e1}  //weight: 10, accuracy: High
        $x_3_2 = "aaae%ae%aae%cCG%'CCRWaae%%aat5ap5%cC" ascii //weight: 3
        $x_3_3 = "drivers\\ui\\NvSmartMax\\NvSmartMaxApp" ascii //weight: 3
        $x_3_4 = "Ru%cV5%at4rRSe'447CGpt5aat5aav" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PasswordStealer_BL_2147827423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PasswordStealer.BL!MTB"
        threat_id = "2147827423"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 4c 00 04 8b 15 [0-4] 02 d0 32 d1 42 88 54 00 04 48 ff c0 48 83 f8 08 72}  //weight: 1, accuracy: Low
        $x_1_2 = {42 0f b6 04 01 2c ?? 42 88 04 01 48 ff c1 48 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

