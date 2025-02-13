rule TrojanDownloader_AndroidOS_Lezok_A_2147788347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Lezok.A"
        threat_id = "2147788347"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Lezok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ApMain.bin" ascii //weight: 2
        $x_2_2 = "getAssetsCoreCode" ascii //weight: 2
        $x_2_3 = "convertUrlToLocalFile" ascii //weight: 2
        $x_2_4 = "formatHexMacToDigits" ascii //weight: 2
        $x_2_5 = "writeRemoteDataToAppdata" ascii //weight: 2
        $x_2_6 = "checkCoreCode() download : " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_Lezok_B_2147788434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Lezok.B"
        threat_id = "2147788434"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Lezok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/android/datasystem/" ascii //weight: 2
        $x_2_2 = "ApCoreLoader" ascii //weight: 2
        $x_2_3 = "ApEnvironment" ascii //weight: 2
        $x_2_4 = "FileDownloadThread" ascii //weight: 2
        $x_2_5 = "DecryptString" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_Lezok_C_2147788435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Lezok.C"
        threat_id = "2147788435"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Lezok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com.iwtiger.plugin" ascii //weight: 10
        $x_5_2 = "downloadFileBeforeExecute" ascii //weight: 5
        $x_5_3 = "convertUrlToLocalFile" ascii //weight: 5
        $x_5_4 = "uploadMauStatus" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

