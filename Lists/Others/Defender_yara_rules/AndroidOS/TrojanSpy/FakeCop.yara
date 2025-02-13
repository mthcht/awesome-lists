rule TrojanSpy_AndroidOS_FakeCop_C_2147809956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCop.C!MTB"
        threat_id = "2147809956"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/system/app/Superuser.apk" ascii //weight: 2
        $x_1_2 = "http://nimabi7.gnway.cc/seoul/kics/login.html" ascii //weight: 1
        $x_1_3 = "com.crazypig.wawa" ascii //weight: 1
        $x_1_4 = "t_flib.db" ascii //weight: 1
        $x_1_5 = "startdelete://" ascii //weight: 1
        $x_1_6 = " Rooted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_FakeCop_D_2147813188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCop.D!MTB"
        threat_id = "2147813188"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 34 0b 00 48 05 01 04 b7 a5 8d 55 4f 05 01 04 d8 04 04 01 28 f6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeCop_B_2147834045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCop.B!MTB"
        threat_id = "2147834045"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OrtApplication" ascii //weight: 1
        $x_1_2 = "R55Receiver" ascii //weight: 1
        $x_1_3 = "loadLibrary" ascii //weight: 1
        $x_1_4 = {6f 10 04 00 01 00 6e 10 03 00 01 00 0c 00 71 20 16 00 01 00 0e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

