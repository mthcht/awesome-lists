rule Trojan_Win32_AtlantidaStealer_GXA_2147902938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AtlantidaStealer.GXA!MTB"
        threat_id = "2147902938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AtlantidaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Browsers\\BroweserInfo.txt" ascii //weight: 1
        $x_1_2 = "Passwords.txt" ascii //weight: 1
        $x_1_3 = "Ethereum\\keystore" ascii //weight: 1
        $x_1_4 = "AtlantidaStealer" ascii //weight: 1
        $x_1_5 = "Exodus\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_6 = "\\Binance\\*.json" ascii //weight: 1
        $x_1_7 = "BinanceWallet" ascii //weight: 1
        $x_1_8 = "CyanoWallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

