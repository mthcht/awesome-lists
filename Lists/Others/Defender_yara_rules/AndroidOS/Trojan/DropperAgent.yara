rule Trojan_AndroidOS_DropperAgent_JY_2147896770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DropperAgent.JY"
        threat_id = "2147896770"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DropperAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SYSTEM_WRITE_REQUIRED" ascii //weight: 2
        $x_2_2 = "DISPLAY_OVER_APPS_INSTALL_REQUIRED" ascii //weight: 2
        $x_2_3 = "PERMISSION_INSTALL_REQUIRED" ascii //weight: 2
        $x_2_4 = "CMD_IGNORE_BATTERY" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_DropperAgent_O_2147908492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DropperAgent.O"
        threat_id = "2147908492"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DropperAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FendouActivity" ascii //weight: 2
        $x_2_2 = "api/Fendouc" ascii //weight: 2
        $x_2_3 = "FendouIManager" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

