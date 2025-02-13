rule Trojan_AndroidOS_Ahmythspy_A_2147783476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.A"
        threat_id = "2147783476"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "x0000fm" ascii //weight: 2
        $x_2_2 = "rbmusic/SMSm" ascii //weight: 2
        $x_1_3 = "/ReadAllTracks.php" ascii //weight: 1
        $x_1_4 = "/sdfs5274/abc.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Ahmythspy_B_2147786700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.B"
        threat_id = "2147786700"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ahmyth/mine/king/ahmyth" ascii //weight: 2
        $x_2_2 = "x0000cn" ascii //weight: 2
        $x_2_3 = "findCameraList" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ahmythspy_C_2147787193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.C"
        threat_id = "2147787193"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/default-dialer" ascii //weight: 1
        $x_1_2 = "INCOMING_CALL_STATE_IDLE" ascii //weight: 1
        $x_1_3 = "/api/v2/alarm/endcall/" ascii //weight: 1
        $x_1_4 = "INCOMING_CALL_STATE_OFFHOOK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ahmythspy_E_2147787764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.E"
        threat_id = "2147787764"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.maluka.latima.NLSCONTROL" ascii //weight: 2
        $x_2_2 = "com.hax4us.haxrat" ascii //weight: 2
        $x_1_3 = "/MainService$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Ahmythspy_F_2147787825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.F"
        threat_id = "2147787825"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.im.devicelogger.managers.ContactsManager" ascii //weight: 2
        $x_2_2 = "com/etechd/l3mon/FileManager" ascii //weight: 2
        $x_2_3 = "test/google/com/CallsManager" ascii //weight: 2
        $x_1_4 = "/CameraManager$1" ascii //weight: 1
        $x_1_5 = "contactsManagerClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Ahmythspy_G_2147789011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.G"
        threat_id = "2147789011"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setFakerCall" ascii //weight: 1
        $x_1_2 = "x0000ca" ascii //weight: 1
        $x_1_3 = "/api/signal/" ascii //weight: 1
        $x_1_4 = "&default_dialer=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ahmythspy_H_2147789042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.H"
        threat_id = "2147789042"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "x0000sm" ascii //weight: 2
        $x_2_2 = "&default_dialer_package_name=" ascii //weight: 2
        $x_1_3 = "singleCommandFeedBack" ascii //weight: 1
        $x_1_4 = "/CallListen$a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Ahmythspy_I_2147829160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.I"
        threat_id = "2147829160"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "x0000mc" ascii //weight: 2
        $x_2_2 = "MicManager" ascii //weight: 2
        $x_2_3 = "CameraManager$1" ascii //weight: 2
        $x_1_4 = "unhide_phone_number" ascii //weight: 1
        $x_1_5 = "x0000fm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Ahmythspy_J_2147829353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.J"
        threat_id = "2147829353"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lahmyth/mine/king/ahmyth/managers/LocManager;" ascii //weight: 2
        $x_2_2 = "x0000cl" ascii //weight: 2
        $x_2_3 = "Disable all notifications of this app." ascii //weight: 2
        $x_2_4 = "MainActivity$$ExternalSyntheticLambda0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ahmythspy_A_2147842815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ahmythspy.A!MTB"
        threat_id = "2147842815"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ahmythspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "asd.apk" ascii //weight: 5
        $x_1_2 = {2f 73 64 63 61 72 64 2f [0-18] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = "startActivityForResult" ascii //weight: 1
        $x_1_4 = "injectedObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

