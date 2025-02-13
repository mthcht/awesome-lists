rule Trojan_Win64_Voldemort_DA_2147920074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Voldemort.DA!MTB"
        threat_id = "2147920074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Voldemort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Voldemort_gdrive_c.dll" ascii //weight: 10
        $x_1_2 = "SparkEntryPoint" ascii //weight: 1
        $x_1_3 = "sheets.googleapis.com" ascii //weight: 1
        $x_1_4 = "/upload/drive/v3/files?uploadType=multipart" ascii //weight: 1
        $x_1_5 = "n/oauth2/v4/token" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

