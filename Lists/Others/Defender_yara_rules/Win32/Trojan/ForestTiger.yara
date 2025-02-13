rule Trojan_Win32_ForestTiger_A_2147892515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ForestTiger.A!dha"
        threat_id = "2147892515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ForestTiger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {41 b8 55 b9 db 02 eb ?? 41 8b c8 c1 e1 05 41 8b c0 c1 f8 02 03 c8 40 0f be c7 03 c8 44 33 c1 48 ff c2}  //weight: 100, accuracy: Low
        $x_100_2 = {ba 55 b9 db 02 84 c9 74 ?? 8d 64 24 00 8b fa 8b da c1 e7 05 c1 fb 02 0f be c9 03 fb 03 f9 8a 4e 01 46 33 d7}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ForestTiger_B_2147892516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ForestTiger.B!dha"
        threat_id = "2147892516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ForestTiger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "4800-84DC-063A6A41C5C" wide //weight: 100
        $x_100_2 = "uTYNkfKxHiZrx3KJ" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

