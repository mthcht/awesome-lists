rule Trojan_Linux_Ladvix_B_2147890468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ladvix.B!MTB"
        threat_id = "2147890468"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ladvix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 54 05 00 75 0f 41 0f b6 34 06 48 63 cb 83 c3 01 40 88 34 0c 48 83 c0 01 48 83 f8 58 75 e1 49 83 c7 01 4c 89 ef e8 c5 f6 ff ff 4c 39 f8 77 c8 4c 89 e7 48 63 db c6 04 1c 00 e8 51 f8 ff ff 48 8b bc 24 08 02 00 00 64 48 33 3c 25 28 00 00 00 75 12 48 81 c4 18 02}  //weight: 1, accuracy: High
        $x_1_2 = "Ym9uZ3JpcHo0amV6dXoK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

