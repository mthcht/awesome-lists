rule Trojan_AndroidOS_Ahmyth_T_2147835037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmyth.T"
        threat_id = "2147835037"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Friend Request Cancelled Successfully" ascii //weight: 1
        $x_1_2 = "uploadOverHttp" ascii //weight: 1
        $x_1_3 = "updateJSONFilePath" ascii //weight: 1
        $x_1_4 = "friendKey=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ahmyth_F_2147841526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmyth.F"
        threat_id = "2147841526"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ahmyth/IOSocket;" ascii //weight: 2
        $x_2_2 = "findCameraList" ascii //weight: 2
        $x_2_3 = "ahmyth/CallsManager;" ascii //weight: 2
        $x_2_4 = "x0000mc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ahmyth_G_2147847777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmyth.G"
        threat_id = "2147847777"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "80876dd5.shop" ascii //weight: 4
        $x_2_2 = "UPLOAD_FILE_AFTER_DATE" ascii //weight: 2
        $x_2_3 = "/serviceteasoft" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Ahmyth_X_2147899817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmyth.X"
        threat_id = "2147899817"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "===:sendRegistrationToServer" ascii //weight: 1
        $x_1_2 = "CLASS_OPPASSWORD_PIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

