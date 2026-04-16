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

rule Trojan_Win64_CryptoStealer_SX_2147967180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealer.SX!MTB"
        threat_id = "2147967180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Global\\LPNMutex4" ascii //weight: 30
        $x_15_2 = "[%s] Potential Capture: %s  %s    %s" ascii //weight: 15
        $x_15_3 = "[%s] Paste Capture: %s" ascii //weight: 15
        $x_10_4 = "[*]done" ascii //weight: 10
        $x_5_5 = "\\WalletWasabi\\Client\\Wallets" ascii //weight: 5
        $x_5_6 = "\\Exodus\\exodus.wallet" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

