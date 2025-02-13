rule Trojan_MacOS_Appetite_A_2147919804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Appetite.A!MTB"
        threat_id = "2147919804"
        type = "Trojan"
        platform = "MacOS: "
        family = "Appetite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 5c 38 00 00 85 c0 0f 8e d7 01 00 00 f6 85 d0 fe ff ff 01 0f 84 00 01 00 00 31 ff 4c 89 ee ba 80 00 00 00 e8 2c 38 00 00 89 85 bc fe ff ff 85 c0 0f 8e 12 ff ff ff 48 8b 0d 9d 46 00 00 83 3d ea 45 00 00 00 74 71 48 85 c9 75 04 89 c2 eb 53}  //weight: 1, accuracy: High
        $x_1_2 = {42 09 9c bd d0 fe ff ff 48 63 05 6d 46 00 00 48 85 c0 7e 2a 48 89 85 c0 fe ff ff c7 85 c8 fe ff ff 00 00 00 00 31 d2 bf 00 04 00 00 ?? ?? ?? ?? ?? ?? ?? 31 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

