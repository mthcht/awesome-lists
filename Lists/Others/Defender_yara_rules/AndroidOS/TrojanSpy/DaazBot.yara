rule TrojanSpy_AndroidOS_DaazBot_A_2147914096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DaazBot.A!MTB"
        threat_id = "2147914096"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DaazBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsRepository" ascii //weight: 1
        $x_1_2 = "screen_reader" ascii //weight: 1
        $x_1_3 = "onUploadLogsClick" ascii //weight: 1
        $x_1_4 = "Lcom/daazbot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_DaazBot_B_2147933110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DaazBot.B!MTB"
        threat_id = "2147933110"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DaazBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitconceLogs.csv" ascii //weight: 1
        $x_1_2 = "bitconceLogs.zip" ascii //weight: 1
        $x_1_3 = "BankSmsDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

