rule TrojanDownloader_MSIL_XWormRAT_A_2147840034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XWormRAT.A!MTB"
        threat_id = "2147840034"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 91 11 ?? 11 ?? 91 61 d2 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_XWormRAT_B_2147843975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XWormRAT.B!MTB"
        threat_id = "2147843975"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Vezkgumqecweusnlfqtqgos.Sbklpzxhrvpoiqrqwhrknkgk" wide //weight: 2
        $x_2_2 = "://cdn.discordapp.com/attachments/" wide //weight: 2
        $x_2_3 = "Qspmqgjmctpbajtke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_XWormRAT_E_2147900582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XWormRAT.E!MTB"
        threat_id = "2147900582"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 8e 69 0b 07 18 5b 0c 16 0d}  //weight: 2, accuracy: High
        $x_2_2 = {06 09 91 13 ?? 06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 ?? 9c 09 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

