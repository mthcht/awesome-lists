rule Ransom_MSIL_EvilBunny_SK_2147944876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/EvilBunny.SK!MTB"
        threat_id = "2147944876"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EvilBunny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$e8ad75bc-a56f-419c-94ea-d9d35329f783" ascii //weight: 1
        $x_1_2 = "Your files are encrypted with a special encryption algorythm" ascii //weight: 1
        $x_1_3 = "EvilBunny_RANSOMWARE\\obj\\Debug\\EvilBunny_RANSOMWARE.pdb" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\BSOD.exe" ascii //weight: 1
        $x_1_5 = "Your files are encrypted by EvilBunny!" ascii //weight: 1
        $x_1_6 = "EvilBunny_RANSOMWARE.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

