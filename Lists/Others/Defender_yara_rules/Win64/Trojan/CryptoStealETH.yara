rule Trojan_Win64_CryptoStealETH_2147811039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealETH"
        threat_id = "2147811039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealETH"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0x333539a9fe84fD78Ce7dEA6b6c906f09a8F39F52" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CryptoStealETH_2147811039_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealETH"
        threat_id = "2147811039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealETH"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0xB239E558D7e61D3b8C20455572cf215d4Cf47e9C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

