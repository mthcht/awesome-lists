rule Trojan_Win64_VenomRat_AVE_2147972547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VenomRat.AVE!MTB"
        threat_id = "2147972547"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 00 00 48 83 c0 01 49 39 c5 75 f4 48 b8 70 00 00 00 00 04 80 00 4c 89 f1 c7 44 24 4c 73 00 00 00 48 89 44 24 70 48 b8 72 00 75 00 6e 00 61 00 48 89 44 24 44 48 8d 44 24 44 48 89 84 24 80 00 00 00 48 89 bc 24 88 00 00 00 c7 84 24 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VenomRat_AMTB_2147973401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VenomRat!AMTB"
        threat_id = "2147973401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VenomRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Silent Updater Started" ascii //weight: 1
        $x_1_2 = "protoolskit.net" ascii //weight: 1
        $x_1_3 = "downandgo.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

