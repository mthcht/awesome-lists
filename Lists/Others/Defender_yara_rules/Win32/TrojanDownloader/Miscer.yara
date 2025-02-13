rule TrojanDownloader_Win32_Miscer_A_2147655168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Miscer.A"
        threat_id = "2147655168"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Miscer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {53 43 48 30 53 54 00 53 43 48 30 53 54}  //weight: 3, accuracy: High
        $x_1_2 = "/rjshengji/ad.exe" wide //weight: 1
        $x_1_3 = "/rjshengji/Alexa.exe" wide //weight: 1
        $x_1_4 = "c:\\SYS\\ad.exe" wide //weight: 1
        $x_1_5 = "c:\\SYS\\Alexa.exe" wide //weight: 1
        $x_1_6 = "url_zhuangtai" ascii //weight: 1
        $x_1_7 = "all_jia_url" ascii //weight: 1
        $x_1_8 = "zcy_click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Miscer_B_2147655699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Miscer.B"
        threat_id = "2147655699"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Miscer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zcy_click" ascii //weight: 1
        $x_1_2 = "zcygo.asp?zcyzzzm=zcyzzzmchakan" wide //weight: 1
        $x_1_3 = "SCH0STS.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

