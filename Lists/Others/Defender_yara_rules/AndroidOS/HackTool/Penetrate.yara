rule HackTool_AndroidOS_Penetrate_A_2147811437_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Penetrate.A!xp"
        threat_id = "2147811437"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Penetrate"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/thomson/thomson.zip" ascii //weight: 1
        $x_1_2 = "://penetrate.underdev.org/s/thomson.service.php?id=" ascii //weight: 1
        $x_1_3 = "DownloadFileTask.java" ascii //weight: 1
        $x_1_4 = "penetrate/lib/core/DownloadFileTask$1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

