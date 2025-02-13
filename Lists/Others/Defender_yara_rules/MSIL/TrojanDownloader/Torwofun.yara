rule TrojanDownloader_MSIL_Torwofun_B_2147697625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Torwofun.B"
        threat_id = "2147697625"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Torwofun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".ru/vk-pro-bot.exe" wide //weight: 1
        $x_1_2 = {2f 00 61 00 70 00 69 00 2f 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 73 00 6f 00 6d 00 65 00 74 00 68 00 69 00 6e 00 67 00 2f 00 76 00 6b 00 70 00 72 00 6f 00 [0-160] 76 00 6b 00 50 00 72 00 6f 00 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 52 00 75 00 6e 00 5c 00 ?? ?? 59 00 65 00 6e 00 69 00 54 00 4d 00 50 00 2e 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Microsoft Update\\UnLoad.exe" wide //weight: 1
        $x_1_5 = "hgtdf73kSdjnaq.exe" wide //weight: 1
        $x_1_6 = {4c 00 69 00 74 00 65 00 44 00 42 00 5c 00 ?? ?? 43 00 72 00 79 00 70 00 74 00 6f 00 44 00 42 00 5c 00 ?? ?? 53 00 79 00 6e 00 63 00 20 00 42 00 61 00 63 00 6b 00 75 00 70 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Torwofun_B_2147697625_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Torwofun.B"
        threat_id = "2147697625"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Torwofun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unloads.in|unloads.ru|dounloads.su|dounloads.net|dounloads.biz" wide //weight: 1
        $x_1_2 = "v5vordmlot5gh36e.onion" wide //weight: 1
        $x_1_3 = "YeniTMP" wide //weight: 1
        $x_1_4 = "Microsoft Update\\UnLoad.exe" wide //weight: 1
        $x_1_5 = "hgtdf73kSdjnaq.exe" wide //weight: 1
        $x_1_6 = {4c 00 69 00 74 00 65 00 44 00 42 00 5c 00 ?? ?? 43 00 72 00 79 00 70 00 74 00 6f 00 44 00 42 00 5c 00 ?? ?? 53 00 79 00 6e 00 63 00 20 00 42 00 61 00 63 00 6b 00 75 00 70 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

