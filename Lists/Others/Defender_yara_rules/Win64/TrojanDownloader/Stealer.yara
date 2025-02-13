rule TrojanDownloader_Win64_Stealer_WE_2147910317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealer.WE!MTB"
        threat_id = "2147910317"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 0f b6 84 ?? ?? ?? ?? ?? 49 ff c0 ff c1 41 30 40 ?? 48 ff c2 49 ff c9 75}  //weight: 2, accuracy: Low
        $x_1_2 = "payload.bin" ascii //weight: 1
        $x_1_3 = "loader.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win64_Stealer_WQ_2147910318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealer.WQ!MTB"
        threat_id = "2147910318"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 33 d2 0f b6 04 2a 49 83 c0 01 83 c1 01 41 30 40 ff 48 83 c2 01 49 83 e9 01}  //weight: 2, accuracy: High
        $x_1_2 = "payload.bin" ascii //weight: 1
        $x_1_3 = "jerry.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win64_Stealer_WZ_2147910319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealer.WZ!MTB"
        threat_id = "2147910319"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be 04 01 48 63 4c 24 10 48 8b 54 24 08 0f be 0c 0a 33 c1 48 63 4c 24 14 48 8b 54 24 30 88 04 0a 8b 44 24 10 83 c0 01 89 44 24 10 eb}  //weight: 2, accuracy: High
        $x_1_2 = "payload.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Stealer_AB_2147910547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealer.AB!MTB"
        threat_id = "2147910547"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 04 01 48 63 4c 24 20 48 8b 54 24 50 0f be 0c 0a 33 c1 48 63 4c 24 24 48 8b 54 24 40 88 04 0a eb}  //weight: 1, accuracy: High
        $x_1_2 = "payload.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Stealer_GA_2147928063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealer.GA!MTB"
        threat_id = "2147928063"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Invoke-WebRequest -Uri" ascii //weight: 1
        $x_1_2 = "https://badlarrysguitars.com" ascii //weight: 1
        $x_1_3 = "TEMP=C:\\TEMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

