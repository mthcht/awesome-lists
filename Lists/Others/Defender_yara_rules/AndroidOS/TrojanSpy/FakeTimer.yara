rule TrojanSpy_AndroidOS_FakeTimer_A_2147652911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeTimer.A"
        threat_id = "2147652911"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeTimer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ".com/check.php?id=" ascii //weight: 10
        $x_10_2 = ".com/rgst5.php" ascii //weight: 10
        $x_1_3 = "&gpsy=" ascii //weight: 1
        $x_1_4 = ".com/send.php?a_id=" ascii //weight: 1
        $x_1_5 = "KitchenTimerService.java" ascii //weight: 1
        $x_1_6 = {26 6d 5f 61 64 64 72 3d ?? ?? 26 74 65 6c 6e 6f 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

