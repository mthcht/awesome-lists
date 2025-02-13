rule Trojan_AndroidOS_SMSend_B_2147786171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSend.B!xp"
        threat_id = "2147786171"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSend"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ht#tp:#/#/mpb#cc.win/#i00" ascii //weight: 1
        $x_1_2 = "createScanner" ascii //weight: 1
        $x_1_3 = "#SM#S_S#ENT" ascii //weight: 1
        $x_1_4 = "upd#a#te d#t set f#lget#=1 w#here sm#s i###n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

