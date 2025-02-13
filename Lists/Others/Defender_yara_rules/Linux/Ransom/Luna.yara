rule Ransom_Linux_Luna_A_2147828252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Luna.A!MTB"
        threat_id = "2147828252"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Luna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 74 24 30 48 8b 54 24 40 4c 89 e7 ff ?? ?? ?? ?? ?? 48 8b 2c 24 48 8b 4c 24 10 be 09 00 00 00 48 8d 3d 53 71 04 00 48 89 ea e8 ?? ?? ?? ?? 89 c3 48 8b 74 24 08 48 85 f6 74 0b ba 01 00 00 00 48 89 ef 41 ?? ?? 80 f3 01 48 8b 74 24 50 48 85 f6 0f 85 02 fc ff ff e9 08 fc ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 fb 49 83 c7 01 49 8b 46 f8 48 83 f8 05 0f ?? ?? ?? ?? ?? 49 8b 46 e8 8b 08 ba 2d 68 65 6c 31 d1 0f b6 50 04 83 f2 70 09 ca 0f ?? ?? ?? ?? ?? 8b 08 ba 2d 66 69 6c 31 d1 0f b6 40 04 83 f0 65 09 c8 0f ?? ?? ?? ?? ?? 4c 39 fd 0f ?? ?? ?? ?? ?? 49 8b 3e 49 8b 76 10 ff ?? ?? ?? ?? ?? 84 c0 0f ?? ?? ?? ?? ?? 48 39 dd 0f ?? ?? ?? ?? ?? 4c 39 fd 0f ?? ?? ?? ?? ?? 49 8d 46 e8 4c 89 24 24 48 8d 0d ca fe ff ff 48 89 4c 24 08}  //weight: 1, accuracy: Low
        $x_1_3 = "Luna.ini.exe.dll.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

