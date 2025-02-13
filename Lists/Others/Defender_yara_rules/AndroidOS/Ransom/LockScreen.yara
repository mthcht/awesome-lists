rule Ransom_AndroidOS_LockScreen_A_2147706616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/LockScreen.A"
        threat_id = "2147706616"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W5kcm9pZF9pZA==" ascii //weight: 1
        $x_1_2 = "W5kcm9pZC5pbnRlbnQuY2F0ZWdvcnkuSE9NR" ascii //weight: 1
        $x_1_3 = "W5kcm9pZC5pbnRlbnQuYWN0aW9uLlVTRVJfUFJFU0VOV" ascii //weight: 1
        $x_1_4 = "W5kcm9pZC5pbnRlbnQuYWN0aW9uLlNDUkVFTl9P" ascii //weight: 1
        $x_1_5 = "W5kZXguaHRtb" ascii //weight: 1
        $x_1_6 = "W5kcm9pZC5hcHAuYWN0aW9uLkFERF9ERVZJQ0VfQURNSU" ascii //weight: 1
        $x_1_7 = "stopForeground" ascii //weight: 1
        $x_1_8 = "/IntrovertedActivity;" ascii //weight: 1
        $x_1_9 = "/UnveilsActivity;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_AndroidOS_LockScreen_A_2147706616_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/LockScreen.A"
        threat_id = "2147706616"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "interrupt insultallation process and cause lost of data" ascii //weight: 1
        $x_1_2 = ".app.action.ADD_DEVICE_ADMIN" ascii //weight: 1
        $x_1_3 = ".SCREEN_OFF" ascii //weight: 1
        $x_1_4 = ".android.settings.DeviceltAdminAdd" ascii //weight: 1
        $x_1_5 = "Baitlock" ascii //weight: 1
        $x_1_6 = "atad fo tsol esuac dna ssecorp noitallatsni tpurretni nac uoygqt LECNAC gnippat yB" ascii //weight: 1
        $x_1_7 = "ddAnimdAeciveD.sgZqWnittes.diordna.moc" ascii //weight: 1
        $x_1_8 = "kcol-ecrof" ascii //weight: 1
        $x_1_9 = "mOZYoc.osouelbbab//:ptth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_AndroidOS_LockScreen_B_2147708044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/LockScreen.B"
        threat_id = "2147708044"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lockphone/killserve$" ascii //weight: 1
        $x_1_2 = {76 61 6c 24 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 61 73 73 77 6f 72 64 5f 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {6b 69 6c 6c 73 65 72 76 65 2e 6a 61 76 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 65 72 6f 2e 6c 6f 63 6b 70 68 6f 6e 65 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_AndroidOS_LockScreen_C_2147753874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/LockScreen.C!MTB"
        threat_id = "2147753874"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 6f 6d 2e 6c 6f 6c 6f 6c 70 2e 4c 6f 63 6b 53 65 72 76 69 63 65 00}  //weight: 2, accuracy: High
        $x_1_2 = {40 69 e2 80 8c 72 68 e2 80 8c 61 63 6b 5f 61 70 e2 80 8c 70}  //weight: 1, accuracy: High
        $x_1_3 = "mamad17m" ascii //weight: 1
        $x_1_4 = "getSystemService(\"layout_inflater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

