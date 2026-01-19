rule Ransom_MSIL_FakeWUCrypt_PA_2147961315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FakeWUCrypt.PA!MTB"
        threat_id = "2147961315"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeWUCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ransomware.php" wide //weight: 3
        $x_1_2 = "BUILD RANSOMEWARE FOR ME" wide //weight: 1
        $x_1_3 = "Ambarawa Cyber Army" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

