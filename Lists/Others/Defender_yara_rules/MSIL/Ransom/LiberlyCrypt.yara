rule Ransom_MSIL_LiberlyCrypt_DA_2147970832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LiberlyCrypt.DA!MTB"
        threat_id = "2147970832"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LiberlyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "schtasks /delete /tn \"LiberlyUpdate\" /f" ascii //weight: 1
        $x_10_4 = "L1b3rly_" ascii //weight: 10
        $x_1_5 = "LbrExfil_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

