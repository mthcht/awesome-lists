rule TrojanDownloader_MacOS_AdLoad_D_2147832429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/AdLoad.D!MTB"
        threat_id = "2147832429"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "AdLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/Contents/Resources/wic.png" ascii //weight: 1
        $x_1_2 = {44 8b 68 04 48 89 df e8 ?? ?? ?? 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2}  //weight: 1, accuracy: Low
        $x_1_3 = "/Contents/Resources/wic.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

