rule TrojanDownloader_O97M_AsyncRat_SS_2147782467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AsyncRat.SS!MTB"
        threat_id = "2147782467"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IAAkAGYAZABzAGYAcwBkAGYAIAA9ACAAIgBmAHMAZgBkAGcAaABmAGQAZABmAGcA" ascii //weight: 1
        $x_1_2 = "Set ZpXcmsCQ = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_3 = "ZpXcmsCQ.Run rdeAjnshv + lqfadUMW + AKrDsxioC, RValue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

