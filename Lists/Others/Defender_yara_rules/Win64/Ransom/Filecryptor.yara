rule Ransom_Win64_Filecryptor_PGH_2147951759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Filecryptor.PGH!MTB"
        threat_id = "2147951759"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "wannadecrypt@fakemail.com" ascii //weight: 5
        $x_5_2 = "OOPS, YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 5
        $x_5_3 = "After payment, contact us" ascii //weight: 5
        $x_5_4 = "DO NOT SHUT DOWN OR RESTART YOUR COMPUTER" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

