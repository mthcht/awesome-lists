rule TrojanDownloader_AndroidOS_FireHelper_A_2147753329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/FireHelper.A"
        threat_id = "2147753329"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "FireHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 00 21 21 35 10 0c 00 48 01 02 00 df 01 01 37 8d 11 4f 01 02 00 d8 00 00 01 28 f4}  //weight: 1, accuracy: High
        $x_1_2 = "firehelper.jar" ascii //weight: 1
        $x_1_3 = "firehelper.dex" ascii //weight: 1
        $x_1_4 = "ZGFsdmlrLnN5c3RlbS5EZXhDbGFzc0xvYWRlcg==" ascii //weight: 1
        $x_1_5 = "co.l.m" ascii //weight: 1
        $x_1_6 = "FIREYMN_2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

