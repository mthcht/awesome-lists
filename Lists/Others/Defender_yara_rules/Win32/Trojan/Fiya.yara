rule Trojan_Win32_Fiya_A_2147689033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiya.A"
        threat_id = "2147689033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\bx1.bak" ascii //weight: 1
        $x_1_2 = "\\bx1.exe" ascii //weight: 1
        $x_1_3 = "fast uax" ascii //weight: 1
        $x_1_4 = {72 62 00 00 77 62 00 00 6f 70 65 6e 00 00 00 00 72 75 6e 61 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fiya_D_2147696011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiya.D"
        threat_id = "2147696011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wlanmgr.dll" ascii //weight: 1
        $x_1_2 = "d3dadapter.dll" ascii //weight: 1
        $x_1_3 = "65524765_673.dat" ascii //weight: 1
        $x_1_4 = "%s\\%s\\Parameters" ascii //weight: 1
        $x_1_5 = {26 61 3d 00 26 70 3d}  //weight: 1, accuracy: High
        $x_1_6 = "Global\\Wlan_Manager_Initialize" ascii //weight: 1
        $x_1_7 = "Global\\D3DAdapter_ServiceEvent" ascii //weight: 1
        $x_1_8 = "%s%c%s%s%c%c%s%s%c%s%c%c%c%s%s%s%s%c%c%s%c%s%s" ascii //weight: 1
        $x_1_9 = "H%c%sQu%c%sIn%co%c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Fiya_E_2147696413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiya.E"
        threat_id = "2147696413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 83 e2 01 8a 92 ?? ?? ?? ?? 30 14 08 40 3b 45 08 72 ec}  //weight: 1, accuracy: Low
        $x_1_2 = "pass=eraijokl489iohj4krds" ascii //weight: 1
        $x_1_3 = {74 47 bf ff 00 00 00 e8 ?? ?? ?? ?? 99 f7 ff ff b5 4c fc ff ff 30 95 ef fc ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = "notificate.php" ascii //weight: 1
        $x_1_5 = {8b c8 83 e1 01 8a 91 ?? ?? ?? ?? 30 94 ?? ?? ?? ff ff 40 3b ?? 72 e9}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 74 18 04 83 c4 04 85 f6 74 18 8d 4d fc 51 6a 40 68 14 04 00 00 53 ff 15 ?? ?? ?? ?? 8b 55 08 52 ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {80 38 4b 57 8d 78 01 0f 85 ?? ?? ?? ?? 80 3f 4b 0f 85 ?? ?? ?? ?? 8b 47 01 8a 4f 05}  //weight: 1, accuracy: Low
        $x_1_8 = {99 b9 ff 00 00 00 f7 f9 ff 74 24 18 30 54 24 5f 8d 44 24 5f}  //weight: 1, accuracy: High
        $x_1_9 = {8a 01 30 02 41 8b c1 2d ?? ?? ?? ?? 3b c6 76 05 b9 ?? ?? ?? ?? 47 42 3b fb 72 e5}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 47 3c 8b 4c 38 78 8b 44 39 20 8b 54 39 18 03 cf 03 c7 89 45 ?? 8b 41 24 03 c7}  //weight: 1, accuracy: Low
        $x_1_11 = {73 2f 8b 4d ?? 0f be 11 8b 45 ?? 0f be 08 33 ca 8b 55 ?? 88 0a 8b 45 ?? 83 c0 01}  //weight: 1, accuracy: Low
        $x_1_12 = {8b 48 28 89 4d ?? 8b 45 ?? 03 45 ?? 6a 00 6a 01 ff 75 ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_13 = {8a 19 30 1a 41 8b d9 2b df 3b 5d ?? 76 02 8b cf 40 42 3b c6 72 ea}  //weight: 1, accuracy: Low
        $x_1_14 = {6a 04 8d 85 ?? ?? ff ff 50 53 c7 85 ?? ?? ff ff b3 15 cf a1}  //weight: 1, accuracy: Low
        $x_1_15 = {c6 02 01 8d 5c 1e ?? 8b c6 3b f3 73 2d 33 f6 80 38 ?? 75 17}  //weight: 1, accuracy: Low
        $x_1_16 = {81 3e b3 15 cf a1 74 0b 4a 4e 83 fa 04 77 f1}  //weight: 1, accuracy: High
        $x_1_17 = {8a 18 30 19 40 8b d8 2b de 3b 5d ?? 76 02 8b c6 47 41 3b fa 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

