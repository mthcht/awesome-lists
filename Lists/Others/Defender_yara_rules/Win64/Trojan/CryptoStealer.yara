rule Trojan_Win64_CryptoStealer_ARA_2147961934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealer.ARA!MTB"
        threat_id = "2147961934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://api.telegram.org/bot%s/sendDocument" ascii //weight: 2
        $x_2_2 = "8148091575:AAEG0CnjuHKohjeiUo52sLZe6ACayN3kVGE" ascii //weight: 2
        $x_2_3 = "Wallets" ascii //weight: 2
        $x_2_4 = "Passwords.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

