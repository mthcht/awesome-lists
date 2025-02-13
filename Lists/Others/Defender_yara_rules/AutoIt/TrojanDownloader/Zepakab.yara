rule TrojanDownloader_AutoIt_Zepakab_YA_2147732013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AutoIt/Zepakab.YA!MTB"
        threat_id = "2147732013"
        type = "TrojanDownloader"
        platform = "AutoIt: AutoIT scripts"
        family = "Zepakab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "= \"img=\" & $" wide //weight: 5
        $x_1_2 = "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_3 = "shellexecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

