rule TrojanDownloader_O97M_Pwrencode_A_2147720685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pwrencode.A"
        threat_id = "2147720685"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pwrencode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wOrKbooK_OPEN(): Call Shell$(\"poWERShElL.Exe -ExECutioNPolicy bYpAsS -NOPrOFiLe -WindOwsTyLe HiddEN -enCodEdCoMMANd IAAoAG4ARQB3AC0AbwBiAGoAZQBjAFQAIABTAHkAUwBUAGUAbQAuAE4AZQB0AC4AVw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

