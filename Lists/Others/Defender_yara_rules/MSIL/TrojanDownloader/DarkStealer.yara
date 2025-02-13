rule TrojanDownloader_MSIL_DarkStealer_NVD_2147819822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DarkStealer.NVD!MTB"
        threat_id = "2147819822"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 50 c3 00 00 8d ?? ?? ?? 01 0a 20 00 04 00 00 8d ?? ?? ?? 01 0a 02 7b}  //weight: 1, accuracy: Low
        $x_1_2 = {02 72 01 00 00 70 20 95 2f 00 00 73}  //weight: 1, accuracy: High
        $x_1_3 = {57 15 a2 01 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 35}  //weight: 1, accuracy: High
        $x_1_4 = "0.tcp.ngrok.io" wide //weight: 1
        $x_1_5 = "hacked by amg" wide //weight: 1
        $x_1_6 = "cmd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

