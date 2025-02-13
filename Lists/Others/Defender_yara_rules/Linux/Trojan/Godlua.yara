rule Trojan_Linux_Godlua_A_2147757728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Godlua.A!MTB"
        threat_id = "2147757728"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Godlua"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 83 ec 1c 6a 00 8d 44 24 14 50 e8 8f e7 ff ff 8b 7c 24 1c b9 d3 4d 62 10 89 f8 c1 ff 1f f7 e9 b9 e8 03 00 00 89 c8 89 d6 f7 6c 24 18 c1 fe 06 29 fe 89 f7 c1 ff 1f 01 f0 11 fa 83 c4 24 5e 5f c3}  //weight: 1, accuracy: High
        $x_1_2 = "d.heheda.tk" ascii //weight: 1
        $x_1_3 = "flash.bat" ascii //weight: 1
        $x_1_4 = "ssl_write_record" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

