rule Ransom_Win64_Grundy_AA_2147895753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Grundy.AA!MTB"
        threat_id = "2147895753"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Grundy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "K:/test/repos/SmallCryptoApp/Win/EnCryptor/TEMP/main.go" ascii //weight: 10
        $x_1_2 = "encoding/asn1.parseBase128Int" ascii //weight: 1
        $x_1_3 = "crypto/elliptic.bigFromHex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

