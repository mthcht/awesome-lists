rule Trojan_MSIL_GenStealer_C_2147982820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GenStealer.C!MTB"
        threat_id = "2147982820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GenStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Binance Chain Wallet" ascii //weight: 1
        $x_1_2 = "BitApp Wallet" ascii //weight: 1
        $x_1_3 = "Terra Station" ascii //weight: 1
        $x_1_4 = "Coin98 Wallet" ascii //weight: 1
        $x_1_5 = "Solana Wallet" ascii //weight: 1
        $x_1_6 = "exodus.wallet" ascii //weight: 1
        $x_1_7 = "Chromium\\User Data\\" ascii //weight: 1
        $x_1_8 = "Brave-Browser\\User Data\\" ascii //weight: 1
        $x_1_9 = "\\Edge\\User Data\\" ascii //weight: 1
        $x_1_10 = "Chromodo\\User Data\\" ascii //weight: 1
        $x_1_11 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_12 = "SELECT Caption FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_13 = "powershell.exe" ascii //weight: 1
        $x_1_14 = "-NoProfile -ExecutionPolicy Bypass -Enc" ascii //weight: 1
        $x_1_15 = "-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

