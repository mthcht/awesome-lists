rule TrojanSpy_AndroidOS_GossRat_A_2147897268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GossRat.A!MTB"
        threat_id = "2147897268"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "gossiper.php" ascii //weight: 5
        $x_1_2 = "/rat/" ascii //weight: 1
        $x_1_3 = "ir/app/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_GossRat_B_2147897269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GossRat.B!MTB"
        threat_id = "2147897269"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saderatweb" ascii //weight: 1
        $x_1_2 = "/SmsMessage" ascii //weight: 1
        $x_1_3 = "web.click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_GossRat_C_2147910824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GossRat.C!MTB"
        threat_id = "2147910824"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "GossiperModel" ascii //weight: 5
        $x_1_2 = "getCardData" ascii //weight: 1
        $x_1_3 = "LastSmsModel" ascii //weight: 1
        $x_1_4 = "sendOtpReqToBK" ascii //weight: 1
        $x_1_5 = "getNationalCodeLink" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_GossRat_D_2147914097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GossRat.D!MTB"
        threat_id = "2147914097"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SrvRead" ascii //weight: 1
        $x_5_2 = "Lcom/psiphon3/app" ascii //weight: 5
        $x_1_3 = "AutoStart" ascii //weight: 1
        $x_5_4 = "KosActivity" ascii //weight: 5
        $x_1_5 = "saderat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_GossRat_E_2147919060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GossRat.E!MTB"
        threat_id = "2147919060"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mellat" ascii //weight: 1
        $x_1_2 = "Lir/expert/sms/Constants" ascii //weight: 1
        $x_1_3 = "Lir/expert/sms/Url" ascii //weight: 1
        $x_1_4 = "Lir/expert/sms/Api" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_GossRat_F_2147926890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GossRat.F!MTB"
        threat_id = "2147926890"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/sadeer/mall" ascii //weight: 1
        $x_1_2 = "getCallLogs" ascii //weight: 1
        $x_1_3 = "saderat" ascii //weight: 1
        $x_1_4 = {74 74 70 73 3a 2f 2f [0-16] 2e 62 69 67 6f 70 61 79 2e 77 6f 72 6b 65 72 73 2e 64 65 76 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

