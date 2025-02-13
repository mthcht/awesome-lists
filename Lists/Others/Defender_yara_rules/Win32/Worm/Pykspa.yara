rule Worm_Win32_Pykspa_A_2147596275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykspa.A"
        threat_id = "2147596275"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SkypeControlAPIDiscover" ascii //weight: 1
        $x_1_2 = "SkypeControlAPIAttach" ascii //weight: 1
        $x_1_3 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = {68 6f 73 74 73 00 00 00 5c 65 74 63 5c 00 00 00 64 72 69 76 65 72 73}  //weight: 1, accuracy: High
        $x_1_5 = "transfer-encoding" ascii //weight: 1
        $x_1_6 = "%d.%d.%d.%d download%d.avast.com" ascii //weight: 1
        $x_1_7 = "%d.%d.%d.%d u%d.eset.com" ascii //weight: 1
        $x_1_8 = "Software\\RMX\\" ascii //weight: 1
        $x_1_9 = "UuidCreate" ascii //weight: 1
        $x_1_10 = "SET USERSTATUS DND" ascii //weight: 1
        $x_1_11 = "SEARCH FRIENDS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Worm_Win32_Pykspa_B_2147596291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykspa.B"
        threat_id = "2147596291"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "echo123" ascii //weight: 10
        $x_10_2 = "Skyuijhsdsd-API-Cddr-" ascii //weight: 10
        $x_10_3 = "SkypeControlAPIAttach" ascii //weight: 10
        $x_1_4 = "chuj.exe" ascii //weight: 1
        $x_1_5 = "drnnctop.exe" ascii //weight: 1
        $x_1_6 = "dideli_papai.scr" ascii //weight: 1
        $x_1_7 = "Soap Bubbles.bmp" ascii //weight: 1
        $x_1_8 = "%d.%d.%d.%d download%d.avast.com" ascii //weight: 1
        $x_1_9 = "how are u ?" ascii //weight: 1
        $x_1_10 = "this (happy) sexy one" ascii //weight: 1
        $x_1_11 = "where I put ur photo" ascii //weight: 1
        $x_1_12 = "your photos looks realy nice" ascii //weight: 1
        $x_1_13 = "what ur friend name wich is in photo ?" ascii //weight: 1
        $x_1_14 = "oops sorry please don't look there" ascii //weight: 1
        $x_1_15 = "look what crazy photo Tiffany sent to me,looks cool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pykspa_C_2147598873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykspa.C"
        threat_id = "2147598873"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 33 f6 83 c4 ?? 39 75 0c 76 2e 8d 45 f0 50 8d 45 f4 50 8d 85 f0 fc ff ff 50 8d 45 fc 50 8d 45 f8 50 33 c0 8a 04 3e 50 e8 ?? ?? ff ff 83 c4 18 88 04 3e 46 3b 75 0c 72 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Pykspa_E_2147632506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykspa.E"
        threat_id = "2147632506"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 00 d0 15 ed 4a 73 0a e8 ?? ?? ?? ?? a3 ?? ?? 45 00 bf c8 32 00 00 66 39 3d ?? ?? 45 00 73 1b e8 ?? ?? ?? ?? 99 b9 50 c3 00 00 f7 f9 03 d7 66 89 15 ?? ?? 45 00}  //weight: 3, accuracy: Low
        $x_2_2 = {68 80 cb a4 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb e9 0a 00 e8 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_3 = {53 6b 79 70 65 2d 41 50 49 2d 54 65 73 74 2d 00 53 6b 79 70 65 43 6f 6e 74 72 6f 6c 41 50 49 44 69 73 63 6f 76 65 72 00 53 6b 79 70 65 43 6f 6e 74 72 6f 6c 41 50 49 41 74 74 61 63 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 45 54 20 50 52 4f 46 49 4c 45 20 46 55 4c 4c 4e 41 4d 45 00 00 00 00 47 45 54 20 50 52 4f 46 49 4c 45 20 50 53 54 4e 5f 42 41 4c 41 4e 43 45}  //weight: 1, accuracy: High
        $x_1_5 = {47 45 54 20 55 53 45 52 20 25 73 20 4f 4e 4c 49 4e 45 53 54 41 54 55 53 00 00 00 00 47 45 54 20 55 53 45 52 20 25 73 20 4d 4f 4f 44 5f 54 45 58 54}  //weight: 1, accuracy: High
        $x_2_6 = {73 6b 79 70 65 00 00 00 20 2d 20 00 74 6f 6f 6c 74 69 70 73 5f 63 6c 61 73 73 33 32 00 00 00 00 74 77 69 74 74 65 72 00}  //weight: 2, accuracy: High
        $x_1_7 = {00 49 46 20 00 43 43 00 00 44 54 00 00 41 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pykspa_F_2147633556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykspa.F"
        threat_id = "2147633556"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SEARCH FRIENDS" ascii //weight: 1
        $x_1_2 = "SkypeControlAPIAttach" ascii //weight: 1
        $x_1_3 = "Skype-API-Test-" ascii //weight: 1
        $x_1_4 = "\\NewSkypeAd.pdb" ascii //weight: 1
        $x_1_5 = "[Ad] Sent all messages" ascii //weight: 1
        $x_1_6 = "[Ad] Shutting down in 5 seconds" ascii //weight: 1
        $x_1_7 = "\\services\\sharedaccess\\parameters\\firewallpolicy\\standardprofile\\authorizedapplications\\list" ascii //weight: 1
        $x_1_8 = "i found an interesting website" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

