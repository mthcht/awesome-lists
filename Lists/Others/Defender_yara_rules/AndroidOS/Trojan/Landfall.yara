rule Trojan_AndroidOS_Landfall_AMTB_2147958363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Landfall!AMTB"
        threat_id = "2147958363"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Landfall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMD_EXEC_FAIL_TO_GET_XPOSED_FRAMEWORK_STATUS" ascii //weight: 1
        $x_1_2 = "DEX_LOAD_MEM_LOAD_CLS_NOT_FOUND" ascii //weight: 1
        $x_1_3 = "DEX_LOAD_DISK_CACHE_NOT_ACCESSIBLE" ascii //weight: 1
        $x_1_4 = "CMD_UNINST_PERSISTENCY_FAIL_UNLINK_PAYLOAD" ascii //weight: 1
        $x_1_5 = "uid=%d, incremental_build: %s, runner: %s" ascii //weight: 1
        $x_1_6 = "bridge_head" ascii //weight: 1
        $x_1_7 = "cnc_hostname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

