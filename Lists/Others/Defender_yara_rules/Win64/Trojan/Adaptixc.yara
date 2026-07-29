rule Trojan_Win64_Adaptixc_PGAC_2147974747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Adaptixc.PGAC!MTB"
        threat_id = "2147974747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Adaptixc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 0f b6 c1 42 0f b6 0c 04 42 88 0c 1c 42 88 14 04 42 0f b6 0c 1c 03 ca 0f b6 d1 0f b6 0c 14 32 4c 07 ff 88 48 ff 49 83 e9 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

