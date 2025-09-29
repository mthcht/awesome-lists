rule HackTool_MacOS_SuspDylibLoader_A_2147953570_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspDylibLoader.A"
        threat_id = "2147953570"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspDylibLoader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "insert_dylib" ascii //weight: 1
        $x_1_2 = "_check_load_commands" ascii //weight: 1
        $x_1_3 = "_codesig_flag" ascii //weight: 1
        $x_1_4 = "_fmemmove" ascii //weight: 1
        $x_1_5 = "_inplace_flag" ascii //weight: 1
        $x_1_6 = "_overwrite_flag" ascii //weight: 1
        $x_1_7 = "_read_load_command" ascii //weight: 1
        $x_1_8 = "_weak_flag" ascii //weight: 1
        $x_1_9 = "memcpy" ascii //weight: 1
        $x_1_10 = "strip-codesig" ascii //weight: 1
        $x_1_11 = "no-strip-codesig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

