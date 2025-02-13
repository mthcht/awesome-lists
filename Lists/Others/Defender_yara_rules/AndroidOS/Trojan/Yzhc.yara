rule Trojan_AndroidOS_Yzhc_A_2147648732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Yzhc.A"
        threat_id = "2147648732"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Yzhc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "businessnamber" ascii //weight: 1
        $x_1_2 = "try new one download" ascii //weight: 1
        $x_1_3 = "sp_blocked_content:" ascii //weight: 1
        $x_1_4 = "&black=" ascii //weight: 1
        $x_1_5 = {26 73 70 6e (75|61) 6d 62 65 72 3d}  //weight: 1, accuracy: Low
        $x_1_6 = "+8613800755500" ascii //weight: 1
        $x_1_7 = "push_show_client:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Yzhc_B_2147679917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Yzhc.B"
        threat_id = "2147679917"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Yzhc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+8613800755500" ascii //weight: 1
        $x_1_2 = "8080/client/loggingall.php?" ascii //weight: 1
        $x_1_3 = "businessnumber" ascii //weight: 1
        $x_1_4 = "spnumcode" ascii //weight: 1
        $x_1_5 = "51widgets.com/ss/service/action.php?action=IsSuccess" ascii //weight: 1
        $x_1_6 = "setYeah" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

