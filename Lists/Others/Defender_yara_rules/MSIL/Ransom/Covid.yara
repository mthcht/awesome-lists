rule Ransom_MSIL_Covid_SK_2147963509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Covid.SK!MTB"
        threat_id = "2147963509"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Covid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "you became a victim of covid-32 ransomware" ascii //weight: 1
        $x_1_2 = "5 mins to pay or else you will lose all your data and also your MBR" ascii //weight: 1
        $x_1_3 = "black_wallpaper.bmp" ascii //weight: 1
        $x_1_4 = "READMEWHATYOUDID.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

