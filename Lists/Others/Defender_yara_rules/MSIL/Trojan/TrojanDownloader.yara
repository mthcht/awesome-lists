rule Trojan_MSIL_TrojanDownloader_Tiny_2147781323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDownloader.Tiny.MM!MTB"
        threat_id = "2147781323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MM: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 20 00 00 01 00 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 26 7e ?? ?? ?? 04 7e ?? ?? ?? 04 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 2b 07 1f 64 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 2d ed 7e ?? ?? ?? 04 16 16 15 28 ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "D:\\Programmierung\\Bingdwn" ascii //weight: 5
        $x_3_3 = "asdf.exe" ascii //weight: 3
        $x_3_4 = "get_IsBusy" ascii //weight: 3
        $x_3_5 = "DownloadFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TrojanDownloader_IAG_2147782383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDownloader.IAG!MTB"
        threat_id = "2147782383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "HGIGJGQPRPSPTPUPVPWPXPYPZPhgihjgonpnqnrn" ascii //weight: 5
        $x_5_2 = "OZxTKXuvsl9D34LWhP" ascii //weight: 5
        $x_5_3 = "SLV0fFIsptsZtjvFft17" ascii //weight: 5
        $x_2_4 = "11111-22222-40001-00001" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TrojanDownloader_MFP_2147783940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDownloader.MFP!MTB"
        threat_id = "2147783940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "89"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "$f39fcc75-d1fe-45d5-ad27-8e7dab088f76" ascii //weight: 50
        $x_50_2 = "$0fd68ed8-3814-46c8-862b-004099d92f70" ascii //weight: 50
        $x_50_3 = "$09bc876a-2699-47bb-ae63-596e41f2a7c4" ascii //weight: 50
        $x_50_4 = "$a01a3ae3-57b5-4ffd-b2d5-239cbdc2be62" ascii //weight: 50
        $x_50_5 = "$9ba3bc85-91b7-4f63-b2b8-fcb94122679b" ascii //weight: 50
        $x_50_6 = "$2ec36c5b-5461-4e6b-bf01-e718ebb4237f" ascii //weight: 50
        $x_50_7 = "$652ee06a-1e27-4ed4-a0e6-15e675078ef2" ascii //weight: 50
        $x_30_8 = {57 55 02 08 09 0b 00 00 00 00 00 00 00 00 00 00}  //weight: 30, accuracy: High
        $x_1_9 = "Invoke" ascii //weight: 1
        $x_1_10 = "IAsyncResult" ascii //weight: 1
        $x_1_11 = "AsyncCallback" ascii //weight: 1
        $x_1_12 = "WebClient" ascii //weight: 1
        $x_1_13 = "DownloadDataAsync" ascii //weight: 1
        $x_1_14 = "ClassLibrary1.dll" ascii //weight: 1
        $x_1_15 = "get_Assembly" ascii //weight: 1
        $x_1_16 = "DownloadDataCompletedEventHandler" ascii //weight: 1
        $x_1_17 = "System.Net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 9 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_TrojanDownloader_TGVC_2147793776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDownloader.TGVC!MTB"
        threat_id = "2147793776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 02 28 ?? ?? ?? 0a 00 02 23 ?? ?? ?? ?? ?? ?? ?? 00 28 ?? ?? ?? 0a 00 72 ?? ?? ?? 70 0a 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 06 00 02 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 18 8d ?? ?? ?? 01 13 ?? 11 ?? 16 06 a2 11 ?? 17 08 a2 11 ?? 0d 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 09 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 26 02}  //weight: 1, accuracy: Low
        $x_1_2 = "InstallUtil.exe" ascii //weight: 1
        $x_1_3 = "SoapHexBinary" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "HtmlDocument" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

