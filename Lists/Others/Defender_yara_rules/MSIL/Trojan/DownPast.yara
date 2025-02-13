rule Trojan_MSIL_DownPast_J_2147743632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DownPast.J!ibt"
        threat_id = "2147743632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DownPast"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 0c 08 28 ?? 00 00 0a 28 ?? 00 00 06 0d 28 ?? 00 00 0a 13 04 72 ?? ?? 00 70 72 ?? ?? 00 70 72 ?? 00 00 70 ?? ?? 00 00 0a 72 ?? ?? 00 70 72 ?? 00 00 70 6f ?? 00 00 0a 13 05 72 ?? ?? 00 70 72 ?? ?? 00 70 72 ?? 00 00 70 ?? ?? 00 00 0a 72 ?? ?? 00 70 72 ?? 00 00 70 6f ?? 00 00 0a 13 06 72 ?? ?? 00 70 72 ?? ?? 00 70 72 ?? 00 00 70 ?? ?? 00 00 0a 72 ?? ?? 00 70 72 ?? 00 00 70 6f ?? 00 00 0a 13 07 72 ?? ?? 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = "/war/moc.nibetsap//:sptth" wide //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "LateCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

