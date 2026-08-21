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

