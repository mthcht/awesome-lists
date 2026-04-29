rule Trojan_MSIL_BrowserStealer_DA_2147965192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BrowserStealer.DA!MTB"
        threat_id = "2147965192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NexusRAT" wide //weight: 2
        $x_2_2 = "No offline log file found. Start offline keylogger first" wide //weight: 2
        $x_2_3 = "_abePayloadData" ascii //weight: 2
        $x_2_4 = "ReadFirefoxPasswords" ascii //weight: 2
        $x_2_5 = "ReadChromiumPasswords" ascii //weight: 2
        $x_2_6 = "passwords_account.json" wide //weight: 2
        $x_2_7 = "/c \"wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /format:list" wide //weight: 2
        $x_2_8 = "ExtractViaChromelevatorAllProfiles" ascii //weight: 2
        $x_2_9 = "HVNC_CLIPBOARD_SET" ascii //weight: 2
        $x_1_10 = "RPROXY_CONNECT_OK" ascii //weight: 1
        $x_1_11 = "app_bound_encrypted_key\":" wide //weight: 1
        $x_1_12 = "|CHROMELEVATOR|TIMEOUT_WAITING_FOR_EXE" wide //weight: 1
        $x_1_13 = "CHROME_V20_FLAG3_XOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BrowserStealer_AAA_2147968035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BrowserStealer.AAA!AMTB"
        threat_id = "2147968035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BrowserStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "\\csharprat\\csharprat\\obj\\Release\\net8.0\\win-x86\\System.Security.Service.pdb" ascii //weight: 15
        $x_1_2 = "Akachu | t.me/ak4chu" wide //weight: 1
        $x_1_3 = "[*] Stealing Telegram sessions..." wide //weight: 1
        $x_1_4 = "Akachu (Telegram Session) -" wide //weight: 1
        $x_1_5 = "credit cards extracted" wide //weight: 1
        $x_1_6 = "Akachu Stealer - Discord Found" wide //weight: 1
        $x_1_7 = "[-] Telegram stealing failed:" wide //weight: 1
        $x_1_8 = "StealWallets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

