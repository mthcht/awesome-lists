rule TrojanSpy_AndroidOS_DomesticKitten_A_2147817543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DomesticKitten.A!MTB"
        threat_id = "2147817543"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DomesticKitten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsobserver" ascii //weight: 1
        $x_1_2 = "/on-answ.php" ascii //weight: 1
        $x_1_3 = "/lg-upld.php" ascii //weight: 1
        $x_1_4 = "rdAllCntcts" ascii //weight: 1
        $x_1_5 = "rdAllCallHis" ascii //weight: 1
        $x_1_6 = "logBrowser" ascii //weight: 1
        $x_1_7 = "logCommandInfo" ascii //weight: 1
        $x_1_8 = "/fle-upld.php?uuid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

