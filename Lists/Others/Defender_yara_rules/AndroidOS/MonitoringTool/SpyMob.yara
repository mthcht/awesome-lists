rule MonitoringTool_AndroidOS_SpyMob_A_328572_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyMob.A!xp"
        threat_id = "328572"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyMob"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/spy2mobile/" ascii //weight: 1
        $x_1_2 = "com.ogp.syscomprocessor.ACTION" ascii //weight: 1
        $x_1_3 = "<TK;TV;>.KeySet;" ascii //weight: 1
        $x_1_4 = "Connectivity changed. Starting background sync" ascii //weight: 1
        $x_1_5 = "http://uonmap.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

