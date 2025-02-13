rule Trojan_Win64_CryptoStealBTC_2147811038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealBTC"
        threat_id = "2147811038"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealBTC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "17c9Y7SgX9thdawyUyHYyEBeA7Ez42rNWg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CryptoStealBTC_2147811038_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealBTC"
        threat_id = "2147811038"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealBTC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bc1qyemv6ufzte2zrvdz5ewesmhpqzjxztza5mp4kq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

