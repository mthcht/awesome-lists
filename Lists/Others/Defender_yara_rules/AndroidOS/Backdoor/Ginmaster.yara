rule Backdoor_AndroidOS_Ginmaster_A_2147789125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Ginmaster.A"
        threat_id = "2147789125"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Ginmaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~qjklGjmv6|w" ascii //weight: 1
        $x_1_2 = "|wovtwy|Gkm{{}kk6|w" ascii //weight: 1
        $x_1_3 = {6a 7d 6c 6d 6a 76 47 7b 77 76 7e 71 7f 36 7c 77}  //weight: 1, accuracy: High
        $x_1_4 = "qvklyttGtqkl6|w" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

