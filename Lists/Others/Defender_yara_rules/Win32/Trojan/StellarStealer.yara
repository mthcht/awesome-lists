rule Trojan_Win32_StellarStealer_GZK_2147943007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StellarStealer.GZK!MTB"
        threat_id = "2147943007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StellarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ethereum\\keystore" ascii //weight: 1
        $x_1_2 = "Data\\Armory" ascii //weight: 1
        $x_1_3 = "\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_4 = "\\wallet.dat" ascii //weight: 1
        $x_1_5 = "Wallets\\Atomic\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_6 = "Wallets\\Ethereum" ascii //weight: 1
        $x_1_7 = "\\SOFTWARE\\Bitcoin\\Bitcoin-Qt" ascii //weight: 1
        $x_1_8 = "Wallets\\Zcash" ascii //weight: 1
        $x_1_9 = "\\TEMP\\BOFUPMJWUSFVSNIBDJEE" ascii //weight: 1
        $x_1_10 = "Wallets\\Bytecoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

