rule PWS_MSIL_RedLineStealer_KMG_2147772883_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/RedLineStealer.KMG!MTB"
        threat_id = "2147772883"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_CreditCards" ascii //weight: 1
        $x_1_2 = "TelegramFiles" ascii //weight: 1
        $x_1_3 = "\\Comodo\\Dragon\\User Data" ascii //weight: 1
        $x_1_4 = "\\Yandex\\YandexBrowser\\User Data" ascii //weight: 1
        $x_1_5 = "\\Mail.Ru\\Atom\\User Data" ascii //weight: 1
        $x_1_6 = "\\Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_1_7 = "\\CryptoTab Browser\\User Data" ascii //weight: 1
        $x_1_8 = "ssfnname\\Coinomi\\wallet_db" ascii //weight: 1
        $x_1_9 = "\\Ethereum\\wallets" ascii //weight: 1
        $x_1_10 = "AccountInfo.txt" ascii //weight: 1
        $x_1_11 = "\\user.configName\\Exodus\\exodus.wallet" ascii //weight: 1
        $x_1_12 = "\\Monero\\wallets" ascii //weight: 1
        $x_1_13 = "Coinomi\\wallet_db" ascii //weight: 1
        $x_1_14 = "ROwindows defender sucksOT\\SecurityCentewindows defender sucksr2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

