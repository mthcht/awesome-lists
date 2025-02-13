rule TrojanSpy_Win32_TinyNuke_A_2147765006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/TinyNuke.A!MTB"
        threat_id = "2147765006"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyNuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://izuw6rclbgl2lwsh.onion/o.php" ascii //weight: 5
        $x_2_2 = "banned_tor_nodes" ascii //weight: 2
        $x_2_3 = "electrum_data\\wallets\\" ascii //weight: 2
        $x_2_4 = "Keylog" ascii //weight: 2
        $x_1_5 = "x64 hooks cleared" ascii //weight: 1
        $x_1_6 = "x32 hooks cleared" ascii //weight: 1
        $x_1_7 = "svchost.exe" ascii //weight: 1
        $x_2_8 = "injects" ascii //weight: 2
        $x_1_9 = "\\\\.\\pipe\\%x" ascii //weight: 1
        $x_1_10 = "Qkkbal" ascii //weight: 1
        $x_2_11 = "%APPDATA%\\Bitcoin\\" ascii //weight: 2
        $x_2_12 = "%APPDATA%\\WalletWasabi\\Client\\Wallets\\" ascii //weight: 2
        $x_2_13 = "%APPDATA%\\Electrum\\wallets\\" ascii //weight: 2
        $x_2_14 = "wallet.dat" ascii //weight: 2
        $x_1_15 = "Encrypt Wallet" ascii //weight: 1
        $x_1_16 = "Unlock Wallet" ascii //weight: 1
        $x_1_17 = "Decrypt Wallet" ascii //weight: 1
        $x_1_18 = "injArch96z.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

