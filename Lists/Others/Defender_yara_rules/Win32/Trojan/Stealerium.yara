rule Trojan_Win32_Stealerium_AO_2147840219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerium.AO!MTB"
        threat_id = "2147840219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 1f 05 e2 9a 46 12 44 2e 0c ef 2a 15 fc 3d 67 3d 07 40 b2 ca 13 08 2a 8b 12 f7 2c 8a 6e aa 10 53 12 2a fc d5 75 f6 5a 9b 40 f6 b0 ab 56 94 25 12 cb 8c 01 7a}  //weight: 2, accuracy: High
        $x_2_2 = {13 1e 2a ee 49 84 3a c9 33 8a 61 a5 17 cc 10 bf 0e 15 53 9c b6 97 8c d5 98 84 e2 29 24 38}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

