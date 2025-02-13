rule Trojan_Win32_Jooblash_A_2147749092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jooblash.A!dha"
        threat_id = "2147749092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jooblash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Down With Bin Salman" ascii //weight: 1
        $x_1_2 = "Down With Saudi Kingdom" ascii //weight: 1
        $x_1_3 = "I'm 22 and looking for fulltime job!" ascii //weight: 1
        $x_1_4 = "elrawdsk.sys" wide //weight: 1
        $x_1_5 = "The Magic Word!" ascii //weight: 1
        $x_1_6 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Jooblash_A_2147749092_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jooblash.A!dha"
        threat_id = "2147749092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jooblash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 44 75 73 74 6d 61 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 44 75 73 74 6d 61 6e 2e 70 64 62 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 44 75 73 74 6d 61 6e 5c 46 75 72 75 74 61 6b 61 5c 64 72 76 5c 61 67 65 6e 74 2e 70 6c 61 69 6e 2e 70 64 62 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 4d 38 49 b9 70 70 70 70 70 70 70 70 44 8b c0 49 c1 e8 03 48 8b 14 08 83 c0 08 49 33 d1 4a 89 14 c3 8b 4d 28 3b c1 72 d6 48 85 ff 74 02 89 0f 48 8b c3 48 8b 5c 24 60 48 83 c4 40}  //weight: 1, accuracy: High
        $x_1_4 = {56 00 42 00 6f 00 78 00 55 00 53 00 42 00 4d 00 6f 00 6e 00 00 00 00 00 56 00 42 00 6f 00 78 00 4e 00 65 00 74 00 41 00 64 00 70 00 00 00 00 00 56 00 42 00 6f 00 78 00 4e 00 65 00 74 00 4c 00 77 00 66 00 00 00 00 00 5c 00 61 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Jooblash_D_2147839151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jooblash.D!dha"
        threat_id = "2147839151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jooblash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

