rule TrojanDownloader_MSIL_NanoBot_PKZM_2147935009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NanoBot.PKZM!MTB"
        threat_id = "2147935009"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0f 72 4d 00 00 70 2b 0f 2b 14 2b 19 2b 1e de 22 73 13 00 00 0a 2b ea 73 14 00 00 0a 2b ea 28 ?? 00 00 0a 2b e5 6f ?? 00 00 0a 2b e0 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

