rule Trojan_AndroidOS_Godfather_A_2147838454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Godfather.A"
        threat_id = "2147838454"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Godfather"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L21wNF9yZWNvcmRlci5waHA" ascii //weight: 1
        $x_1_2 = "send_all_permission" ascii //weight: 1
        $x_1_3 = "setting_app_notifi_list" ascii //weight: 1
        $x_1_4 = "Invalid OPENSSH file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Godfather_B_2147840875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Godfather.B"
        threat_id = "2147840875"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Godfather"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/a/c/g0f9" ascii //weight: 1
        $x_1_2 = "0e16854d4fc83d86c4520a2c62253614db301c5b1554ba2f202b184434598b3d" ascii //weight: 1
        $x_1_3 = "035a62447c629d9fd856858cbfe905c9" ascii //weight: 1
        $x_1_4 = "881c435e192cfdb1c6b6447944713f2cf725fa2ca2035624cd166a0c08487c0c" ascii //weight: 1
        $x_1_5 = "a8889eed2eb55cccfac2c91b88842cd8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Godfather_C_2147844350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Godfather.C!MTB"
        threat_id = "2147844350"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Godfather"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "02f287b512cc707107c0d1d398f99a5197f9f79acb1e57b531a1242c76145243" ascii //weight: 5
        $x_1_2 = "3e84588e88e84c24e17bc37603f86309de85926f38a7f7e720dce2ed54d22d6e" ascii //weight: 1
        $x_1_3 = "b69794d5d7010e11c89daac815c6cdb7" ascii //weight: 1
        $x_1_4 = "03dfdc291f025df51804e3b4baffc7ea" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Godfather_D_2147852547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Godfather.D"
        threat_id = "2147852547"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Godfather"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URL_APPLOGS" ascii //weight: 1
        $x_1_2 = "sendSmstoerver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Godfather_D_2147852547_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Godfather.D"
        threat_id = "2147852547"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Godfather"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/mp4_recorder.php" ascii //weight: 2
        $x_2_2 = "gettop_app_db" ascii //weight: 2
        $x_2_3 = "godfather" ascii //weight: 2
        $x_2_4 = "app_perm_check" ascii //weight: 2
        $x_2_5 = "sms_default_click" ascii //weight: 2
        $x_2_6 = "access_use_service" ascii //weight: 2
        $x_2_7 = "send_all_permission" ascii //weight: 2
        $x_2_8 = "start_ussd" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Godfather_L_2147926433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Godfather.L"
        threat_id = "2147926433"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Godfather"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cHJvdGVjdDIwMjBfc3Ry" ascii //weight: 2
        $x_2_2 = "Y29tLmNydXppZXJvLmJ1bWFyZWU=" ascii //weight: 2
        $x_2_3 = "dm5jcmVzZXQ=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

