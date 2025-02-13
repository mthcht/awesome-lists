rule Trojan_Win32_Kriskynote_B_2147696448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kriskynote.B!dha"
        threat_id = "2147696448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KingOfPhantom0308_20140826" ascii //weight: 2
        $x_1_2 = {56 56 ff 74 24 14 89 44 24 1c 50 57 ff d3 50 57 56 56 ff d5 8b 44 24 10 5e}  //weight: 1, accuracy: High
        $x_1_3 = {57 48 83 ec 40 b8 01 00 00 00 3b d0 0f 85 fd 00 00 00 ff 15 3e 10 00 00 85 c0 0f 84 e3 00 00 00 83 64 24 58 00 ff 15 d3 0f 00 00 48 8d 54 24 58 48 8b c8 ff 15 15 10 00 00 b9 02 00 00 00 39 4c 24 58 48 8b f0 0f 8c b8 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kriskynote_B_2147696448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kriskynote.B!dha"
        threat_id = "2147696448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%temp%\\chk_harddisk_state.dll" wide //weight: 2
        $x_1_2 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

