rule Trojan_Win64_PureCrypt_WQ_2147939731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PureCrypt.WQ!MTB"
        threat_id = "2147939731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PureCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 40 48 00 15 13 80 33 c9 48 89 48 08 c7 40 48 01 15 13 80 c7 40 48 0e 00 07 80 48 8b 0d 99 9f 15 00 48 8d 49 08 48 8b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PureCrypt_PCW_2147953078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PureCrypt.PCW!MTB"
        threat_id = "2147953078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PureCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c1 48 8d b4 24 00 09 00 00 48 89 f2 41 b8 04 01 00 00 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

