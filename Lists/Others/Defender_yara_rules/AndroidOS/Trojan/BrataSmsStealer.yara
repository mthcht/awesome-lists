rule Trojan_AndroidOS_BrataSmsStealer_D_2147822790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BrataSmsStealer.D"
        threat_id = "2147822790"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BrataSmsStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_send_blockincomingmsgs" ascii //weight: 2
        $x_2_2 = "_wsh_connecttoyou" ascii //weight: 2
        $x_2_3 = "_wsh_sendmsgtophone" ascii //weight: 2
        $x_1_4 = "_send_newsmstoadmin" ascii //weight: 1
        $x_1_5 = "_send_socket_data" ascii //weight: 1
        $x_1_6 = "_connecttoserver" ascii //weight: 1
        $x_1_7 = "_intwhoisconnectedtome " ascii //weight: 1
        $x_1_8 = "_add_con_todb" ascii //weight: 1
        $x_1_9 = "_getemails" ascii //weight: 1
        $x_1_10 = "_findcontactsbymail" ascii //weight: 1
        $x_1_11 = "_findallcontacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

