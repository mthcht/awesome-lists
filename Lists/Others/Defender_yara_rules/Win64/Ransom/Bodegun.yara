rule Ransom_Win64_Bodegun_YAA_2147915514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Bodegun.YAA!MTB"
        threat_id = "2147915514"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Odyssey-RansomWare\\RansomWare-encrypt\\x64\\Release\\RansomWare-encrypt.pdb" ascii //weight: 1
        $x_1_2 = "Your Files Have Been Encrypted" ascii //weight: 1
        $x_1_3 = "README.txt" ascii //weight: 1
        $x_1_4 = "Hacked By NetX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

