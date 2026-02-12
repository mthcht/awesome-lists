rule Ransom_MSIL_FakeCoder_MX_2147962956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FakeCoder.MX!MTB"
        threat_id = "2147962956"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaCrydemo.pdb" ascii //weight: 1
        $x_1_2 = "bitcoin.org" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "WanaDecryptor" wide //weight: 1
        $x_1_5 = "wallpaper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

