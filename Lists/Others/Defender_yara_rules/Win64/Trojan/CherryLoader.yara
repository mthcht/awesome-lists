rule Trojan_Win64_CherryLoader_RX_2147903864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CherryLoader.RX!MTB"
        threat_id = "2147903864"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CherryLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 c6 48 b8 ab aa aa aa aa aa aa aa 48 89 d7 48 f7 eb 48 01 da 48 d1 fa 48 8d 14 52 48 89 d8 48 29 d0 0f b6 14 1f 48 83 f8 03 72 b9}  //weight: 5, accuracy: High
        $x_1_2 = "Go build ID: \"4pnnN7IdNKjzHuOELYFM/uFzb4lTFk4VxecmwXJnl/Pql-vF9kSZvjveUjLSd2/wf-VFTg8PbTL82teVhG0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

