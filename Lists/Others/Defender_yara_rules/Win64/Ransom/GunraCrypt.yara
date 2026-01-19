rule Ransom_Win64_GunraCrypt_PA_2147961303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GunraCrypt.PA!MTB"
        threat_id = "2147961303"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GunraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "R3ADM3.txt" ascii //weight: 3
        $x_1_2 = "%s/%s.keystore" ascii //weight: 1
        $x_1_3 = "Your data has been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

