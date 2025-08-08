rule Trojan_Win32_JSCealz_Z_2147948827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JSCealz.Z!MTB"
        threat_id = "2147948827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JSCealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crypto" wide //weight: 1
        $x_1_2 = "wallets" wide //weight: 1
        $x_1_3 = "telegram" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "machineId" wide //weight: 1
        $x_1_6 = "socket.removeListener(" wide //weight: 1
        $x_1_7 = "wallet_password" wide //weight: 1
        $x_1_8 = "stealth/evasions/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

