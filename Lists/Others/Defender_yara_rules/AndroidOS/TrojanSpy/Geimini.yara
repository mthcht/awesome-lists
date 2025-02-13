rule TrojanSpy_AndroidOS_Geimini_A_2147641579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Geimini.A"
        threat_id = "2147641579"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Geimini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 69 2c 78 69 61 6f 6c 75 ?? ?? 68 69 2c 6c 69 71 69 61 6e ?? ?? 63 6f 6d 6d 61 6e 64 20 6f 6b ?? ?? 62 79 65}  //weight: 1, accuracy: Low
        $x_1_2 = {41 64 41 63 74 69 76 69 74 79 0c 00 63 6f 6d (2e|2f) 67 65 69 6e 69 6d 69}  //weight: 1, accuracy: Low
        $x_1_3 = "processDOWNLOAD_FAILUE_Action" ascii //weight: 1
        $x_1_4 = "processPARSE_FAILUE_Action" ascii //weight: 1
        $x_1_5 = "TRANSACT_FAILUE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

