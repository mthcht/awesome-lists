rule Ransom_Win64_CryptoLock_ZK_2147976764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CryptoLock.ZK!MTB"
        threat_id = "2147976764"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DEADLINE EXPIRED - KEYS DESTROYED" ascii //weight: 3
        $x_3_2 = "!!!  ALL YOUR FILES HAVE BEEN ENCRYPTED  !!!" ascii //weight: 3
        $x_3_3 = "Do not attempt to decrypt files manually" ascii //weight: 3
        $x_3_4 = "=== CRYPTLOCK" ascii //weight: 3
        $x_3_5 = "To recover your files, you must pay the decryption fee" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_CryptoLock_AK_2147976833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CryptoLock.AK!MTB"
        threat_id = "2147976833"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 33 c8 48 8b c1 49 33 c5 48 c1 e0 11 48 33 c8 49 33 cd 48 c1 e9 20 42 30 0c 0a 49 ff c1 4c 8b 85 ?? 01 00 00 49 8b c0 48 8b 95 ?? 01 00 00 48 2b c2 4c 3b c8 72}  //weight: 5, accuracy: Low
        $x_3_2 = "Exec\\x64\\Release\\idkikdikdikdikdidkdiddi.pdb" ascii //weight: 3
        $x_2_3 = "ALL USER DATA HAS BEEN PERMANENTLY DELETED" ascii //weight: 2
        $x_2_4 = "YOUR FILES AND YOUR DEVICE HAS BEEN SEIZED BY C4N0F FAGGOT" ascii //weight: 2
        $x_2_5 = ".locked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

