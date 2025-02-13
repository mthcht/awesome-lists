rule Trojan_Win64_Caynamer_ACAY_2147926686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Caynamer.ACAY!MTB"
        threat_id = "2147926686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Caynamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 4f ec c4 4e 4d 8d 40 01 f7 eb c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 0f b6 c3 ff c3 2a c1 04 38 41 30 40 ff 83 fb 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

