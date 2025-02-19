rule TrojanDownloader_O97M_DBatLoader_RV_2147929689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/DBatLoader.RV!MTB"
        threat_id = "2147929689"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DBatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http.open\"get\",plpl,falsexhttp.send" ascii //weight: 1
        $x_1_2 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_DBatLoader_RV_2147929689_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/DBatLoader.RV!MTB"
        threat_id = "2147929689"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DBatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=\"t\"&\"p:/\"&\"/147.124.216.113/" ascii //weight: 1
        $x_1_2 = "http.open\"get\",plpl,falsexhttp.send" ascii //weight: 1
        $x_1_3 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_DBatLoader_VRD_2147929824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/DBatLoader.VRD!MTB"
        threat_id = "2147929824"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DBatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"t\" & \"p:/\" & \"/87.120.113.91/image" ascii //weight: 1
        $x_1_2 = "http.open\"get\",plpl,falsexhttp.send" ascii //weight: 1
        $x_1_3 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

