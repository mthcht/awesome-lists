rule TrojanDownloader_MSIL_NanoCore_C_2147824441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NanoCore.C!MTB"
        threat_id = "2147824441"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 11 01 20 80 f9 37 03 6f 03 00 00 0a 13 02 38 00 00 00 00 dd}  //weight: 10, accuracy: High
        $x_10_2 = {38 00 00 00 00 00 00 11 ?? 16 73 ?? 00 00 0a 73 ?? 00 00 0a 13 1d 00 00 00 0a 13 02}  //weight: 10, accuracy: Low
        $x_10_3 = "Replace" ascii //weight: 10
        $x_10_4 = "GetResponseStream" ascii //weight: 10
        $x_10_5 = "WebRequest" ascii //weight: 10
        $x_10_6 = "SecurityProtocolType" ascii //weight: 10
        $x_10_7 = "ToArray" ascii //weight: 10
        $x_10_8 = "ProcessWindowStyle" ascii //weight: 10
        $x_10_9 = "GetMethod" ascii //weight: 10
        $x_10_10 = "CreateDelegate" ascii //weight: 10
        $x_10_11 = "GetTypes" ascii //weight: 10
        $x_1_12 = ".jpg" wide //weight: 1
        $x_1_13 = ".png" wide //weight: 1
        $x_1_14 = ".bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

