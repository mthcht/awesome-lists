rule Ransom_MSIL_ZiggyCrypter_PA_2147771809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ZiggyCrypter.PA!MTB"
        threat_id = "2147771809"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZiggyCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted" ascii //weight: 1
        $x_1_2 = "MindLated.jpg" wide //weight: 1
        $x_1_3 = "http://fixfiles.xyz/ziggy/api/info.php" wide //weight: 1
        $x_1_4 = "Ziggy Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

