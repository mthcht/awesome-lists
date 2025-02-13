rule TrojanDownloader_VBA_Esascl_2147822442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:VBA/Esascl!MTB"
        threat_id = "2147822442"
        type = "TrojanDownloader"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Esascl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell(\"cmd/ccertutil.exe-urlcache-split-f" ascii //weight: 1
        $x_1_2 = "://assistance-espace-client.com/calc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

