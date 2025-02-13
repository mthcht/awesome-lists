rule Trojan_Win32_LoaderMulti_RD_2147833125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LoaderMulti.RD!MTB"
        threat_id = "2147833125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LoaderMulti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 57 56 53 8b 6c 24 14 8b 74 24 18 8b 7c 24 1c 85 ff 74 3e b9 00 00 00 00 89 c8 ba 00 00 00 00 f7 74 24 20 c1 ea 02 0f be 5c 15 00 6b db 57 b8 ed 73 48 4d f7 eb 89 d0 c1 f8 04 c1 fb 1f 29 d8 ba 9a ff ff ff 0f af c2 30 04 0e 83 c1 01 39 f9 75 c7 5b 5e 5f 5d c3 b8 81 01 00 00 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

