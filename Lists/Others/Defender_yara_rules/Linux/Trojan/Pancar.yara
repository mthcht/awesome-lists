rule Trojan_Linux_Pancar_A_2147893579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pancar.A!MTB"
        threat_id = "2147893579"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pancar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/centreon/www/include/tools/check.sh" ascii //weight: 1
        $x_1_2 = {31 db 48 c1 fd 03 48 83 ec 08 e8 35 fe ff ff 48 85 ed 74 1e 0f 1f 84 00 00 00 00 00 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea 48 83 c4 08 5b 5d 41 5c 41 5d 41 5e 41 5f}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 3d c8 08 20 00 00 74 1e b8 00 00 00 00 48 85 c0 74 14 55 bf 20 0e 60 00 48 89 e5 ff d0 5d e9 7b ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

