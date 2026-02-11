rule Ransom_Win64_Darkness_GVA_2147962876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Darkness.GVA!MTB"
        threat_id = "2147962876"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Darkness"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".darkness" ascii //weight: 1
        $x_1_2 = "Solana" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "YOUR FILE HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_5 = "PAY BY THE SPECIFIED TIME, OTHERWISE YOU WILL SUFFER THE CONSEQUENCES" ascii //weight: 1
        $x_1_6 = "The tool works. You can test it on 2 files for free first." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

