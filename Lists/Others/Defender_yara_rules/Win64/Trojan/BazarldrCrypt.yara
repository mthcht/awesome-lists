rule Trojan_Win64_BazarldrCrypt_SN_2147766790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarldrCrypt.SN!MTB"
        threat_id = "2147766790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarldrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d3 f7 d3 44 21 cb 83 e2 05 09 da 44 31 ca 29 c2 f6 d2 48 8b 06 48 8b 5c ?? ?? 88 14 18 bb ?? ?? ?? ?? 48 8b 7c ?? ?? e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

