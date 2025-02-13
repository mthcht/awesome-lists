rule Trojan_MSIL_Vigorf_MA_2147806282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vigorf.MA!MTB"
        threat_id = "2147806282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vigorf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7fb03cb0-f117-4424-ace2-5b59c734c56d" ascii //weight: 1
        $x_1_2 = "get_AutoKyKx" ascii //weight: 1
        $x_1_3 = "KYKeoxe" ascii //weight: 1
        $x_1_4 = "get_autopkvip1" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "GetFolderPath" ascii //weight: 1
        $x_1_7 = "checkFileToDownload" ascii //weight: 1
        $x_1_8 = "GetFileNameWithoutExtension" ascii //weight: 1
        $x_1_9 = "CreateShortcut" ascii //weight: 1
        $x_1_10 = "get_login" ascii //weight: 1
        $x_1_11 = "get_AutoupdateINI" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "get_AutoPKFile" ascii //weight: 1
        $x_1_14 = "FileStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

