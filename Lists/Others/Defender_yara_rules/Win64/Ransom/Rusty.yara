rule Ransom_Win64_Rusty_MX_2147920225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rusty.MX!MTB"
        threat_id = "2147920225"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rusty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Rusty Ransomware" ascii //weight: 5
        $x_1_2 = "ransomnote.exe" ascii //weight: 1
        $x_1_3 = "encrypt_date.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

