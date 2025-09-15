rule Ransom_Win64_Bak_AN_2147952237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Bak.AN!MTB"
        threat_id = "2147952237"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Bak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your important files have been encrypted" ascii //weight: 1
        $x_1_2 = "Recovery without our decryption tool is impossible" ascii //weight: 1
        $x_1_3 = "Receive decryptor and recover all files" ascii //weight: 1
        $x_1_4 = "help@axelglue.store" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

