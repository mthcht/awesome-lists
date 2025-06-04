rule Trojan_Win64_SvcStealer_BCP_2147934073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SvcStealer.BCP!MTB"
        threat_id = "2147934073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SvcStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2d d1 de a9 68 88 44 24 4a 69 c0 cf 1c 13 00 2d d1 de a9 68 88 44 24 4b 69 c0 cf 1c 13 00 2d d1 de a9 68 88 44 24 4c 69 c0 cf 1c 13 00 2d d1 de a9 68 88 44 24 4d}  //weight: 2, accuracy: High
        $x_1_2 = "/svcstealer/get.php" ascii //weight: 1
        $x_1_3 = "185.81.68.15" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SvcStealer_RJP_2147937594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SvcStealer.RJP!MTB"
        threat_id = "2147937594"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SvcStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 0c 25 30 00 00 00 48 8b 51 60 48 89 5a 10 48 8b 45 e8 48 03 c3 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SvcStealer_CM_2147942571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SvcStealer.CM!MTB"
        threat_id = "2147942571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SvcStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "9APARW83Z6" ascii //weight: 2
        $x_2_2 = "62.60.226.191" ascii //weight: 2
        $x_1_3 = "uid=%s&ver=%s" ascii //weight: 1
        $x_1_4 = "SELECT name_on_card, expiration_month, expiration_year, card_numb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SvcStealer_DIG_2147942778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SvcStealer.DIG!MTB"
        threat_id = "2147942778"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SvcStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 ca 8d 42 87 ff c2 42 30 44 21 0a 83 fa 57 72 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

