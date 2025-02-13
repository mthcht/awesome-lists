rule TrojanSpy_AndroidOS_Anubis_A_2147743956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Anubis.A!MTB"
        threat_id = "2147743956"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "|Attempt to remove malware " ascii //weight: 2
        $x_1_2 = "|startrat=" ascii //weight: 1
        $x_1_3 = "Info + Grabber cards" ascii //weight: 1
        $x_1_4 = "str_push_fish" ascii //weight: 1
        $x_1_5 = "spamSMS" ascii //weight: 1
        $x_1_6 = "perehvat_sws" ascii //weight: 1
        $x_1_7 = "|Start injection " ascii //weight: 1
        $x_1_8 = "buttonPlayProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Anubis_B_2147754060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Anubis.B!MTB"
        threat_id = "2147754060"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start Activity Inject" ascii //weight: 1
        $x_1_2 = "Grabber cards mini" ascii //weight: 1
        $x_1_3 = "fafa.php?f=" ascii //weight: 1
        $x_1_4 = {2f 6f 31 6f 2f 61 [0-3] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_5 = "str_push_fish" ascii //weight: 1
        $x_1_6 = "Started for Disable Play Protect Action" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Anubis_YA_2147754386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Anubis.YA!MTB"
        threat_id = "2147754386"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "R3JhYmJlciBjYXJkcyBtaW5p" ascii //weight: 1
        $x_1_2 = "aHRtbGxvY2tlcg==" ascii //weight: 1
        $x_1_3 = {2f 6f 31 6f 2f 61 [0-3] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = "|Start injection" ascii //weight: 1
        $x_1_5 = "PGFtb3VudD4=" ascii //weight: 1
        $x_1_6 = "SetJavaScriptEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Anubis_C_2147763369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Anubis.C!MTB"
        threat_id = "2147763369"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lyed/fbdbk/vze/ifdf$ifdf" ascii //weight: 1
        $x_1_2 = "killBackgroundProcesses" ascii //weight: 1
        $x_1_3 = "createScreenCaptureIntent" ascii //weight: 1
        $x_1_4 = "SEND_SMS" ascii //weight: 1
        $x_1_5 = {2f 6f 31 6f 2f 61 [0-3] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Anubis_D_2147807680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Anubis.D!MTB"
        threat_id = "2147807680"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 21 72 35 20 3c 00 52 62 4d 00 d8 02 02 01 d4 22 00 01 59 62 4d 00 52 62 4e 00 54 63 4c 00 52 64 4d 00 44 03 03 04 b0 32 d4 22 00 01 59 62 4e 00 52 62 4d 00 52 63 4e 00 54 64 4c 00 70 40 ?? ?? 26 43 54 62 4c 00 54 63 4c 00 52 64 4d 00 44 03 03 04 54 64 4c 00 52 65 4e 00 44 04 04 05 b0 43 d4 33 00 01 44 02 02 03 48 03 07 00 b7 32 8d 22 4f 02 01 00 d8 00 00 01 28 c4 11 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Anubis_F_2147822343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Anubis.F!MTB"
        threat_id = "2147822343"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/fastflashlightsupp" ascii //weight: 1
        $x_1_2 = "urlAdminPanel" ascii //weight: 1
        $x_1_3 = "urlDownloadApp" ascii //weight: 1
        $x_1_4 = "startLoader" ascii //weight: 1
        $x_1_5 = "install_non_market_apps" ascii //weight: 1
        $x_1_6 = "getLaunchIntentForPackage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

