rule Trojan_Win64_Cryptor_LM_2147959871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptor.LM!MTB"
        threat_id = "2147959871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Attempts to restore your data with third party software as Photorec, RannohDecryptor etc." ascii //weight: 10
        $x_20_2 = "As soon as we receive the payment you will get the decryption tool and" ascii //weight: 20
        $x_5_3 = "File encrypted successfully:" ascii //weight: 5
        $x_3_4 = "DO NOT MOVE the encrypted files." ascii //weight: 3
        $x_2_5 = "Send us 2-3 different random files and you will get them decrypted." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

