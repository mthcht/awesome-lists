rule Trojan_Win32_BabyLonRat_AB_2147978744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BabyLonRat.AB!MTB"
        threat_id = "2147978744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BabyLonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 8b 5d 10 8b c7 99 f7 7d 14 8a 0c 1a f6 d1 00 0e 46 47}  //weight: 2, accuracy: High
        $x_1_2 = {56 ff 75 10 ff 75 0c 8b 70 18 6a 17 5f 0f b7 16 8d 46 08 66 3b d7 8d 4e 04 0f 44 c8 51 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

