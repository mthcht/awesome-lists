rule Trojan_AndroidOS_Ginmaster_A_2147851622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ginmaster.A"
        threat_id = "2147851622"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ginmaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/gamesns/model" ascii //weight: 1
        $x_1_2 = "finish, recordtime" ascii //weight: 1
        $x_1_3 = "Sign in to Gamesns" ascii //weight: 1
        $x_1_4 = "checkinDetailsText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ginmaster_H_2147899818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ginmaster.H"
        threat_id = "2147899818"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ginmaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/installer_adv_succ_log.php" ascii //weight: 1
        $x_1_2 = "/installerKing.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ginmaster_P_2147901921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ginmaster.P"
        threat_id = "2147901921"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ginmaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sorry: One level - one tap.." ascii //weight: 1
        $x_1_2 = "[MKLWU]GYHHGQ\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

