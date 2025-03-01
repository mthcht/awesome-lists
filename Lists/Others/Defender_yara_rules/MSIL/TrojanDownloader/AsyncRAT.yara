rule TrojanDownloader_MSIL_AsyncRat_CCHZ_2147905552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRat.CCHZ!MTB"
        threat_id = "2147905552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 14 11 14 6f ?? 00 00 0a 26 73 ?? ?? ?? ?? 13 15 11 15 72 ?? 06 00 70 73 ?? ?? ?? 0a 06 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 16 11 16 72}  //weight: 1, accuracy: Low
        $x_1_2 = "DisableCMD" wide //weight: 1
        $x_1_3 = "Sideload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

