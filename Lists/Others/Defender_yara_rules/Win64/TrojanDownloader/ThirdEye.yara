rule TrojanDownloader_Win64_ThirdEye_SK_2147850738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ThirdEye.SK!MTB"
        threat_id = "2147850738"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ThirdEye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url=shlalala.ru" ascii //weight: 1
        $x_1_2 = "url=kaluga-news.ru" ascii //weight: 1
        $x_2_3 = "@SJ\\[APGQZXT\\[JUF_USE_DES_KEY_OUF_SMARTCARD_REQaRk\\M__c[" ascii //weight: 2
        $x_2_4 = "C:\\Users\\Public\\calc.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win64_ThirdEye_SL_2147850739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ThirdEye.SL!MTB"
        threat_id = "2147850739"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ThirdEye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YJcTEWW[HcGERXcG" ascii //weight: 2
        $x_2_2 = "PkQd\\U[LeVGYY]JeTUZXKWYdUFXX\\TWIdFQQT\\ZKdJSHW" ascii //weight: 2
        $x_2_3 = "3rd_eye" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

