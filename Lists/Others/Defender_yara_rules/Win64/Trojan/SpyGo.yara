rule Trojan_Win64_SpyGo_MR_2147906452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyGo.MR!MTB"
        threat_id = "2147906452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keylog sent. Keylog" ascii //weight: 1
        $x_1_2 = {48 8d 15 c5 2c 0e 00 48 89 54 24 30 e8 1b 41 de ff 48 8d 0d 34 af 01 00 48 89 4c 24 38 48 89 44 24 40 48 8b 1d 6b ff 26 00 48 8d 05 3c 3d 0e 00 48 8d 4c 24 28 bf 02 00 00 00 48 89 fe e8 4a 47 e9 ff 31 c0 48 8d 1d 9c 77 07 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

