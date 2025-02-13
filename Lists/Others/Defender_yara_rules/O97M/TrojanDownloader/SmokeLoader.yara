rule TrojanDownloader_O97M_SmokeLoader_PA_2147768850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SmokeLoader.PA!MTB"
        threat_id = "2147768850"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://bemojo.com/ds/161120.gif" ascii //weight: 1
        $x_1_2 = "https://btchs.com.br/ds/161120.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_SmokeLoader_RV_2147922176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SmokeLoader.RV!MTB"
        threat_id = "2147922176"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jfvvvsa9icdodhrwoi8vz29vzg1hc3rlcnnwb3j0dw5py3vtlnj1l2xvywqvc3zjlmv4zs" ascii //weight: 1
        $x_1_2 = "powershell-e$ccc;\",6)application.screenupdating=trueendsub" ascii //weight: 1
        $x_1_3 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

