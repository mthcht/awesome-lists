rule Ransom_Win64_WannaCry_SQI_2147964287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WannaCry.SQI!MTB"
        threat_id = "2147964287"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WannaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@WanaDecryptor@.exe" ascii //weight: 2
        $x_1_2 = "@Please_Read_Me@.txt" ascii //weight: 1
        $x_1_3 = "WannaCry_AES_KEY" ascii //weight: 1
        $x_1_4 = ".WNCRY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

