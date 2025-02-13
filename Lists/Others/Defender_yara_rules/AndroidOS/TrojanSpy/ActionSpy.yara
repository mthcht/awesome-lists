rule TrojanSpy_AndroidOS_ActionSpy_A_2147783549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/ActionSpy.A"
        threat_id = "2147783549"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "ActionSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com/isyjv/klxblnwc" ascii //weight: 10
        $x_5_2 = "/proc/self/cmdline" ascii //weight: 5
        $x_5_3 = "export LD_LIBRARY_PATH=/vendor/lib:/system/lib" ascii //weight: 5
        $x_1_4 = "pm install -r" ascii //weight: 1
        $x_1_5 = "Microlog" ascii //weight: 1
        $x_1_6 = "sp_server" ascii //weight: 1
        $x_1_7 = "sp_uuid" ascii //weight: 1
        $x_1_8 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cX3l079JIH2I7G0SnEJ2R58uyh1peh4sju" ascii //weight: 1
        $x_1_9 = "/.utsk/conf/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

