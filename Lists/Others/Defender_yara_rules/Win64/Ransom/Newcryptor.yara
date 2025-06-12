rule Ransom_Win64_Newcryptor_YAE_2147943509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Newcryptor.YAE!MTB"
        threat_id = "2147943509"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Newcryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateEncryptor" ascii //weight: 1
        $x_10_2 = "Your network is hacked" wide //weight: 10
        $x_10_3 = "files are encrypted" wide //weight: 10
        $x_1_4 = "newcryptor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

