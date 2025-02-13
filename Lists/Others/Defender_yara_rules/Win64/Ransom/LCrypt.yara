rule Ransom_Win64_LCrypt_PAA_2147797868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LCrypt.PAA!MTB"
        threat_id = "2147797868"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_lcry_enc" ascii //weight: 1
        $x_1_2 = "Oops,Data lost!" ascii //weight: 1
        $x_1_3 = "But you closed LCRY!" ascii //weight: 1
        $x_1_4 = "f1les have b33n encrypt3d by m3" ascii //weight: 1
        $x_1_5 = "Your AES key is in LCRY's memory." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

