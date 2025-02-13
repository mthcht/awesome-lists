rule Ransom_Win64_Albabat_AC_2147900041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Albabat.AC!MTB"
        threat_id = "2147900041"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Albabat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MIIBCgKCAQEAw/4Mpnw7yV9NDzjISgNesWSHj7A" ascii //weight: 1
        $x_1_2 = "The \" Ransomware\" is a cross-platform ransomware that encrypts" ascii //weight: 1
        $x_1_3 = "files on your machine have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Albabat_YAA_2147900111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Albabat.YAA!MTB"
        threat_id = "2147900111"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Albabat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grisu.rs" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\SystemDisableTaskMgr" ascii //weight: 1
        $x_1_3 = "wallpaper_albabat.jpg" ascii //weight: 1
        $x_1_4 = "-----BEGIN RSA PUBLIC KEY----" ascii //weight: 1
        $x_1_5 = "ENCRYPTED" ascii //weight: 1
        $x_1_6 = "decrypt your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

