rule Worm_Win32_Flame_A_2147657363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flame.gen!A"
        threat_id = "2147657363"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flame"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c8 c1 e9 18 8b d8 c1 eb 10 32 cb 8b d8 c1 eb 08 32 cb 32 c8 28 0e 46 4a 75}  //weight: 2, accuracy: High
        $x_2_2 = {33 c0 c3 66 81 3e 4d 5a 75 f6 8b 46 3c 03 c6}  //weight: 2, accuracy: High
        $x_2_3 = {81 f9 db df ac a2 74 18 81 f9 fc fe ba b0}  //weight: 2, accuracy: High
        $x_1_4 = "UPDT_SYNC_MTX_TME" wide //weight: 1
        $x_1_5 = "TH_POOL_SHD_" wide //weight: 1
        $x_2_6 = {8b 4e 1c ff 75 08 41 51 50 89 46 0c e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Flame_B_2147657364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flame.gen!B"
        threat_id = "2147657364"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flame"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {66 81 3f 4d 5a 89 85 e4 fe ff ff 0f 85 a3 00 00 00 8b 47 3c 8d 74 38 18 6a 04 56 ff d3 85 c0 0f 85 8f 00 00 00 66 81 3e 0b 01}  //weight: 4, accuracy: High
        $x_1_2 = "UPDT_SYNC_MTX_TME" wide //weight: 1
        $x_1_3 = "TH_POOL_SHD_" wide //weight: 1
        $x_1_4 = "S:(ML;;NW;;;LW)D:(A;OICI;GA;;;WD)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Flame_C_2147657365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flame.gen!C"
        threat_id = "2147657365"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flame"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 48 11 83 c0 0b 0f af c8 8b d1 c1 ea 08 8b c2 33 c1 c1 e8 10 33 c2 33 c1}  //weight: 4, accuracy: High
        $x_2_2 = {8a 06 56 88 47 ff ff 15 ?? ?? ?? ?? 80 3e 63 88 07 7c 5a 33 c0 53}  //weight: 2, accuracy: Low
        $x_1_3 = "RpcNsBindingInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Flame_D_2147657433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flame.gen!D"
        threat_id = "2147657433"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flame"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 29 83 f8 0a 74 11 83 e8 5a f7 d8 1b c0 25 f8 07 00 00 83 c0 08 eb 57}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 57 66 8b 46 09 8d 7e 0b 50 57}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 75 11 ff d6 3d 30 04 00 00 74 08 53 53 53 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Flame_E_2147657441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flame.gen!E"
        threat_id = "2147657441"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flame"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 8d 48 11 83 c0 0b 0f af c8 8b c1 8b d1 25 00 00 ff 00 c1 ea 08 33 c2 8b d1 c1 e8 08 66 81 e2 00 ff 33 c2 c1 e8 08 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = "\\Global\\JcvEvent3" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Symantec\\" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\FarStone\\" ascii //weight: 1
        $x_1_5 = "root@195.97.78.162 -P 443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

