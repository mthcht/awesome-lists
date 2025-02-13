rule TrojanDownloader_Win32_Valfroc_A_2147611154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Valfroc.A"
        threat_id = "2147611154"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Valfroc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "84A504C1-802C-479F-9DD8-BE5B899A5805" ascii //weight: 1
        $x_1_3 = "54D8E0D7-FC69-468E-8B36-E5C9B1BDC7AB" ascii //weight: 1
        $x_1_4 = "4AC82601-FCB3-4333-8493-590B18F0F52D" wide //weight: 1
        $x_1_5 = "gmarket.co.kr" wide //weight: 1
        $x_1_6 = "dnshop.com" ascii //weight: 1
        $x_1_7 = "ilikeclick.com" ascii //weight: 1
        $x_1_8 = "interich.com" ascii //weight: 1
        $x_1_9 = "linkprice.com" ascii //weight: 1
        $x_1_10 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_11 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_12 = "InternetOpenA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

