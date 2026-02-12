rule Ransom_Win64_CipherWolf_MX_2147962958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CipherWolf.MX!MTB"
        threat_id = "2147962958"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CipherWolf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Our ransomware CipherWolf has encrypted all files." ascii //weight: 5
        $x_1_2 = "deleteshadows/all/quiet" ascii //weight: 1
        $x_1_3 = "schtasks/create/s/tn" ascii //weight: 1
        $x_1_4 = "Temp\\payload.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

