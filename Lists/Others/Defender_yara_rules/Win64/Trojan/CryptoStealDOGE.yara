rule Trojan_Win64_CryptoStealDOGE_2147811040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealDOGE"
        threat_id = "2147811040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealDOGE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D9Xq8SJK6y1MG5Wt8AqaridnFFmBicWbgw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CryptoStealDOGE_2147811040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealDOGE"
        threat_id = "2147811040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealDOGE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DBKQJmkykTtn1j7B4dnu3tPEt5JzxU3NgN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

