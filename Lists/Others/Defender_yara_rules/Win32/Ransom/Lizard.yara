rule Ransom_Win32_Lizard_PAA_2147779919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lizard.PAA!MTB"
        threat_id = "2147779919"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lizard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your SERVER/COMPUTER is encrypted by us" ascii //weight: 1
        $x_1_2 = "cryptopp-CRYPTOPP" ascii //weight: 1
        $x_1_3 = "ENCRYPTER@server" ascii //weight: 1
        $x_1_4 = "\\#ReadThis.HTA" ascii //weight: 1
        $x_1_5 = "King Of Ransom" ascii //weight: 1
        $x_1_6 = "key.txt.LIZARD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

