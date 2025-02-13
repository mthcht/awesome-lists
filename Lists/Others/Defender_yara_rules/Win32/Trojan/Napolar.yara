rule Trojan_Win32_Napolar_A_2147682583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.A"
        threat_id = "2147682583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "v=%d.%d&u=%s&c=%s&s=%s&w=%d." ascii //weight: 1
        $x_1_2 = {8b 10 81 fa 50 45 00 00 0f 85 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 8b 42 78 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 50 18 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Napolar_A_2147682583_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.A"
        threat_id = "2147682583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 89 45 ?? 8b 45 [0-16] 2d 00 10 00 00 05 00 02 00 00 89 45 ?? 8b 45 ?? 8b 40 18 8b 55 ?? 2b 42 34 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? 6a 00 6a 01 6a 00 ff 55}  //weight: 10, accuracy: Low
        $x_10_2 = {05 75 4c 6f 63 6b 07 53 79 73 49 6e 69 74 06 53 79 73 74 65 6d 8d 40 00 00 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {8d 45 fc 50 6a 40 6a 06 68 a4 42 40 00 6a ff e8 ?? ?? ?? ?? 3c 01 75 36 b8 a4 42 40 00 c6 00 68 b8 ?? ?? 40 00 ba a4 42 40 00 42 89 02 b8 a4 42 40 00 83 c0 05 c6 00 c3 8d 45 fc 50 8b 45 fc 50 6a 06 68 a4 42 40 00 6a ff}  //weight: 10, accuracy: Low
        $x_1_4 = {50 6a 00 6a 00 68 03 80 00 00 8b 45 fc 50}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 f8 40 25 ff 00 00 00 89 45 f8 8b 45 f8 8b 84 85 ec fb ff ff 03 45 f4 25 ff 00 00 00 89 45 f4 8b 45 f8 8a 84 85 ec fb ff ff 88 45 f3 8b 45 f4 8b 84 85 ec fb ff ff 8b 55 f8 89 84 95 ec fb ff ff 33 c0 8a 45 f3 8b 55 f4 89 84 95 ec fb ff ff 8b 45 f8 8b 84 85 ec fb ff ff 8b 55 f4 03 84 95 ec fb ff ff 25 ff 00 00 00 8a 84 85 ec fb ff ff 8b 55 08 03 55 fc 30 02 ff 45 fc ff 4d ec 0f 85 7b ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Napolar_B_2147684606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.B"
        threat_id = "2147684606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "v=%d.%d&u=%s&c=%s&s=%s&w=%d." wide //weight: 1
        $x_1_2 = {6a 00 8b 43 10 50 8b c7 03 43 14 50 8b 45 ?? 03 43 0c 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c3 28 4e 75}  //weight: 1, accuracy: Low
        $x_1_3 = {81 38 50 45 00 00 75 ?? 8b 45 ?? 8b 70 78 03 f3 8b 46 18 48 85 c0 72 ?? 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Napolar_D_2147687112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.D"
        threat_id = "2147687112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 08 81 e2 ff ff ff 00 8b 34 b7 31 d6 89 f0 66 39 cb 77 ?? f7 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 4d 5a 00 00 75 2f 8b 73 3c 81 c6 f8 00 00 00 89 f0 c1 f8 1f bf 00 00 00 00 39 f8}  //weight: 1, accuracy: High
        $x_1_3 = "0=%d.%d&1=%s&2=%s&3=%s&4=%d.%d.%d&5=%d&6=%s" ascii //weight: 1
        $x_1_4 = "\\\\.\\pipe\\npx86_Services" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Napolar_A_2147688146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.gen!A"
        threat_id = "2147688146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 04 3b 02 c2 8a b0 ?? ?? ?? 00 88 b1 ?? ?? ?? 00 88 90 ?? ?? ?? 00 fe c1 75 da 61 c9 c2 08 00 55 8b ec 60 8b 7d 0c 8b 75 08 85 ff 74 44 b8 00 00 00 00 8b d0 8b ca 8b d9}  //weight: 1, accuracy: Low
        $x_1_2 = {02 04 3b 02 c2 8a b0 ?? ?? ?? 00 88 b1 ?? ?? ?? 00 88 90 ?? ?? ?? 00 fe c1 75 da 61 c9 c2 08 00 55 8b ec 60 8b 7d 0c 8b 75 08 85 ff 74 41 33 c0 33 d2 33 c9 33 db}  //weight: 1, accuracy: Low
        $x_2_3 = {ff 75 0c ff 75 08 e8 58 00 00 00 c9 c2 10 00 55 8b ec 60 b8 fc fd fe ff b9 40 00 00 00 89 04 ?? ?? ?? ?? 00 2d 04 04 04 04 49 75 f1 33 c0 8b 7d 08 33 db 8b 75 0c eb 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Napolar_B_2147688147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.gen!B"
        threat_id = "2147688147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "S:(ML;;NW;;;LW)D:(A;;0x12019b;;;WD)" ascii //weight: 1
        $x_1_2 = "v=%d.%d&u=%s&c=%s&s=%s&w=%d." ascii //weight: 1
        $x_1_3 = "p=%s&h=%s&u=%s&s=%08lX" ascii //weight: 1
        $x_1_4 = {66 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 00 2e 72 64 61 74 61 00 2e 74 65 78 74 [0-4] 53 53 4c [0-4] 53 4f 4c 41 52}  //weight: 1, accuracy: Low
        $x_1_5 = "\\\\.\\pipe\\napSolar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Napolar_B_2147688849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.gen!B!!Napolar"
        threat_id = "2147688849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Napolar: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "S:(ML;;NW;;;LW)D:(A;;0x12019b;;;WD)" ascii //weight: 1
        $x_1_2 = "v=%d.%d&u=%s&c=%s&s=%s&w=%d." ascii //weight: 1
        $x_1_3 = "p=%s&h=%s&u=%s&s=%08lX" ascii //weight: 1
        $x_1_4 = {66 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 00 2e 72 64 61 74 61 00 2e 74 65 78 74 [0-4] 53 53 4c [0-4] 53 4f 4c 41 52}  //weight: 1, accuracy: Low
        $x_1_5 = "\\\\.\\pipe\\napSolar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Napolar_GND_2147897607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Napolar.GND!MTB"
        threat_id = "2147897607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Napolar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "j@hS0@" ascii //weight: 1
        $x_1_2 = "j@h.1@" ascii //weight: 1
        $x_1_3 = "j@hX1@" ascii //weight: 1
        $x_1_4 = "longkeydoesntmatter3431131" ascii //weight: 1
        $x_1_5 = "test.txt encrypted as test.txt" ascii //weight: 1
        $x_1_6 = "hi how are you encrypted as %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

