rule Trojan_Win64_Trickbot_I_2147742083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.I"
        threat_id = "2147742083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 31 41 33 33 89 32 48 83 c2 04 49 83 c3 04 48 83 c1 04 49 3b c9 49 0f 43 c8 4d 3b da}  //weight: 1, accuracy: High
        $x_1_2 = {b8 08 00 00 00 89 44 ?? ?? 89 44 ?? ?? 89 44 ?? ?? 89 44 ?? ?? b8 04 00 00 00 89 44 ?? ?? 89 44 ?? ?? b9 40 10 00 00 ba 02 00 00 00 41 b8 04 00 00 00 41 b9 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c0 e0 02 41 8b d2 c0 ea 04 80 e2 03 0a d0 88 54 ?? ?? 41 c0 e2 04 44 8a 5c ?? ?? 41 8b c3 c0 e8 02 24 0f 41 0a c2 41 c0 e3 06 44 02 5c ?? ?? 88 44 ?? ?? 44 88 5c ?? ?? 88 17 33 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 b8 08 02 00 00 10 66 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {c0 27 09 00 ba 90 5f 01 00 41 b8 90 5f 01 00 41 b9 20 bf 02 00 48 8b c8 48 8b c8 ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ba 00 08 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {8b c8 48 69 c9 09 23 ed 58 48 c1 e9 20 8b d0 2b d1 d1 ea 03 d1 c1 ea 06 6b ca 5f f7 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Trickbot_WA_2147745313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.WA!MTB"
        threat_id = "2147745313"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InfMachine" ascii //weight: 10
        $x_1_2 = "%s x64" ascii //weight: 1
        $x_1_3 = "Size - %d kB" ascii //weight: 1
        $x_1_4 = "\\\\%s\\IPC$" ascii //weight: 1
        $x_1_5 = "MACHINE IN WORKGROUP" ascii //weight: 1
        $x_1_6 = "LDAP://%ls" ascii //weight: 1
        $x_1_7 = "(objectCategory=computer)(userAccountControl" ascii //weight: 1
        $x_1_8 = "{001677D0-FD16-11CE-ABC4-02608C9E7553}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_SA_2147746149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SA!MSR"
        threat_id = "2147746149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Update your Microsoft Word" wide //weight: 1
        $x_1_2 = "C:\\TEMP\\MHk6kyiq.Z6O" wide //weight: 1
        $x_1_3 = "IMPORTANT" wide //weight: 1
        $x_1_4 = "MPGoodStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_SS_2147752807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SS"
        threat_id = "2147752807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {04 75 d4 8a [0-48] c0 e8 04 24 03 0a [0-32] c0 e9 02 80 e1 0f 0a [0-32] 83 fe 02 7c 28 8d 4e fe 48 ff c1 ff ce 41 88 07 83 fe 01 74 15 b8 01 00 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_3 = {48 b9 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff e0 48 8b 4c ?? ?? 48 8b 54}  //weight: 10, accuracy: Low
        $x_10_4 = {83 f8 68 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 70 75 [0-26] 83 f8 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_SS_2147752807_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SS"
        threat_id = "2147752807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {04 75 d4 8a [0-48] c0 e9 02 80 e1 0f 0a [0-32] c0 e8 04 24 03 0a [0-32] 83 fe 02 7c 28 8d 4e fe 48 ff c1 ff ce 41 88 07 83 fe 01 74 15 b8 01 00 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_3 = {48 b9 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff e0 48 8b 4c ?? ?? 48 8b 54}  //weight: 10, accuracy: Low
        $x_10_4 = {83 f8 68 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 70 75 [0-26] 83 f8 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_D_2147752872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.D!!Trickbot.D"
        threat_id = "2147752872"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {04 75 d4 8a [0-48] c0 e8 04 24 03 0a [0-32] c0 e9 02 80 e1 0f 0a [0-32] 83 fe 02 7c 28 8d 4e fe 48 ff c1 ff ce 41 88 07 83 fe 01 74 15 b8 01 00 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_3 = {48 b9 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff e0 48 8b 4c ?? ?? 48 8b 54}  //weight: 10, accuracy: Low
        $x_10_4 = {83 f8 68 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 70 75 [0-26] 83 f8 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_D_2147752872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.D!!Trickbot.D"
        threat_id = "2147752872"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {04 75 d4 8a [0-48] c0 e9 02 80 e1 0f 0a [0-32] c0 e8 04 24 03 0a [0-32] 83 fe 02 7c 28 8d 4e fe 48 ff c1 ff ce 41 88 07 83 fe 01 74 15 b8 01 00 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_3 = {48 b9 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff e0 48 8b 4c ?? ?? 48 8b 54}  //weight: 10, accuracy: Low
        $x_10_4 = {83 f8 68 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 74 75 ?? ?? ?? ?? ?? ?? 83 f8 70 75 [0-26] 83 f8 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_WB_2147753201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.WB!MTB"
        threat_id = "2147753201"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "socksbot.dll" ascii //weight: 10
        $x_1_2 = "file = \"bcconfig" ascii //weight: 1
        $x_1_3 = "Can't connect to server" ascii //weight: 1
        $x_1_4 = "Can't create io_service" ascii //weight: 1
        $x_1_5 = "WSARecv time out" ascii //weight: 1
        $x_1_6 = "Disconnecting" ascii //weight: 1
        $x_1_7 = "Invalid parentID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_STA_2147754481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.STA"
        threat_id = "2147754481"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 69 88 [0-16] 83 f0 65 [0-16] 83 f0 78 [0-16] 83 f0 70 [0-16] 83 f0 6c [0-16] 83 f0 6f 83 f0 72 83 f0 65 [0-16] 83 f0 2e [0-16] 83 f0 65 [0-16] 83 f0 78 [0-16] 83 f0 65}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f0 63 88 [0-16] 83 f0 68 [0-16] 83 f0 72 [0-16] 83 f0 6f [0-16] 83 f0 6d [0-16] 83 f0 65 [0-16] 83 f0 2e [0-16] 83 f0 65 [0-16] 83 f0 78 [0-16] 83 f0 65}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 ed 6b c6 45 ee 6a c6 45 ef 6d c6 45 f0 6b c6 45 f1 69 c6 45 f2 76 c6 45 f3 34 c6 45 f4 6b c6 45 f5 7e c6 45 f6 6b}  //weight: 1, accuracy: High
        $x_1_4 = "payload64.dll" ascii //weight: 1
        $x_1_5 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Trickbot_STA_2147754483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.STA!!Trickbot.STA"
        threat_id = "2147754483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "STA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 69 88 [0-16] 83 f0 65 [0-16] 83 f0 78 [0-16] 83 f0 70 [0-16] 83 f0 6c [0-16] 83 f0 6f 83 f0 72 83 f0 65 [0-16] 83 f0 2e [0-16] 83 f0 65 [0-16] 83 f0 78 [0-16] 83 f0 65}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f0 63 88 [0-16] 83 f0 68 [0-16] 83 f0 72 [0-16] 83 f0 6f [0-16] 83 f0 6d [0-16] 83 f0 65 [0-16] 83 f0 2e [0-16] 83 f0 65 [0-16] 83 f0 78 [0-16] 83 f0 65}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 ed 6b c6 45 ee 6a c6 45 ef 6d c6 45 f0 6b c6 45 f1 69 c6 45 f2 76 c6 45 f3 34 c6 45 f4 6b c6 45 f5 7e c6 45 f6 6b}  //weight: 1, accuracy: High
        $x_1_4 = "payload64.dll" ascii //weight: 1
        $x_1_5 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Trickbot_PA_2147756517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.PA!MTB"
        threat_id = "2147756517"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 88 7c 24 ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? ?? 44 24 [0-16] 75}  //weight: 1, accuracy: Low
        $x_1_2 = "Grab_Passwords_Chrome" ascii //weight: 1
        $x_1_3 = "\\Google\\Chrome\\User Data\\Default\\History.bak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_M_2147756596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.M"
        threat_id = "2147756596"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 01 75 [0-64] 8b ?? 41 33 ?? 89 ?? 48 83 ?? 04 49 83 ?? 04 48 83 ?? 04 49 3b ?? 49 0f 43 ?? 4d 3b ?? 72 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_SH_2147756906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SH"
        threat_id = "2147756906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b 5a 40 49 8b 7a 38 49 8b 5a 30 4d 8b 4a 28 4d 8b 42 20 49 8b 4a 10 49 8b 52 18}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 44 24 38 4c 89 5c 24 30 48 89 7c 24 28 48 89 5c 24 20 eb 56 [0-96] ff 12}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 86 a8 00 00 00 c7 46 58 00 00 00 00 48 8b 4e 08 ff 56 30 48 8b 0e 48 8b 56 08 41 b8 ff ff ff ff 45 33 c9 ff 56 18}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 0e 48 8b 56 08 45 33 c0 45 33 c9 ff 56 18 48 8b 0e ff 56 28 48 c7 06 00 00 00 00 48 8b 4e 08 ff 56 28 48 c7 46 08 00 00 00 00 33 c9 ff 56 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Trickbot_SH_2147756906_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SH"
        threat_id = "2147756906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 58 50 48 8b 78 48 4c 8b 50 40 4c 8b 58 38 4c 8b 70 30 4c 8b 48 28 4c 8b 40 20 48 8b 48 10 48 8b 50 18}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 5c 24 40 48 89 7c 24 38 4c 89 54 24 30 4c 89 5c 24 28 4c 89 74 24 20 eb 50 [0-96] ff 10}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 50 50 4c 8b 58 48 48 8b 78 40 48 8b 58 38 4c 8b 70 30 4c 8b 48 28 4c 8b 40 20 48 8b 48 10 48 8b 50 18}  //weight: 1, accuracy: High
        $x_1_4 = {4c 89 54 24 40 4c 89 5c 24 38 48 89 7c 24 30 48 89 5c 24 28 4c 89 74 24 20 eb 50 [0-96] ff 10}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 58 48 48 8b 78 40 4c 8b 50 38 4c 8b 58 30 4c 8b 48 28 4c 8b 40 20 48 8b 48 10 48 8b 50 18 48 89 5c 24 38 48 89 7c 24 30 4c 89 54 24 28 4c 89 5c 24 20 ff 10}  //weight: 1, accuracy: High
        $x_1_6 = {4c 8b 50 48 4c 8b 58 40 48 8b 78 38 48 8b 58 30 4c 8b 48 28 4c 8b 40 20 48 8b 48 10 48 8b 50 18 4c 89 54 24 38 4c 89 5c 24 30 48 89 7c 24 28 48 89 5c 24 20 ff 10}  //weight: 1, accuracy: High
        $x_1_7 = {4c 8b 40 20 48 8b 48 10 48 8b 50 18 ff 10 eb 36}  //weight: 1, accuracy: High
        $x_1_8 = {48 8b 0e 48 8b 56 08 45 33 c0 45 33 c9 ff 56 18 48 8b 4e 08 ff 56 28 48 c7 46 08 00 00 00 00 48 8b 0e ff 56 28 48 c7 06 00 00 00 00 33 c9 ff 56 38}  //weight: 1, accuracy: High
        $x_1_9 = {48 8b 0e 48 8b 56 08 45 33 c0 45 33 c9 ff 56 18 48 8b 4e 08 ff 56 28 48 8b 0e ff 56 28 48 c7 46 08 00 00 00 00 48 c7 06 00 00 00 00 33 c9 ff 56 38}  //weight: 1, accuracy: High
        $x_1_10 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 48 89 56 70 4c 89 46 78 4c 89 8e 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {8b c9 48 89 8e 88 00 00 00 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20}  //weight: 1, accuracy: High
        $x_1_12 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 4c 89 8e 80 00 00 00 8b c9}  //weight: 1, accuracy: High
        $x_1_13 = {48 89 8e 88 00 00 00 48 89 56 70 4c 89 46 78 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win64_Trickbot_SKE_2147763251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SKE"
        threat_id = "2147763251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {c0 e2 04 8a ?? ?? ?? 8b ?? c0 ?? 02 80 ?? 0f [0-1] 0a ?? 88 ?? ?? ?? c0 ?? 06 02 ?? ?? ?? 88 4a 00 48 83 ?? 01 48 83 ?? 04 75 ?? 8a [0-4] 8a ?? ?? ?? c0 ?? 02 [0-1] 8b ?? c0 ?? 04 [0-2] 03 0a ?? 88}  //weight: 30, accuracy: Low
        $x_10_2 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_3 = {fd ff ff 7f 74 ?? 49 83 ?? 01 48 83 ?? 01 49 8b ?? 75 ?? eb 30 00 47 0f ?? ?? ?? 66 45 ?? ?? 74 ?? 66 44 ?? ?? 48 83 ?? 02 4c ?? ?? ff 49 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_SKD_2147763253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SKD!!Trickbot.SKD"
        threat_id = "2147763253"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "SKD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {c0 e2 04 8a ?? ?? ?? 8b ?? c0 ?? 02 80 ?? 0f [0-1] 0a ?? 88 ?? ?? ?? c0 ?? 06 02 ?? ?? ?? 88 4a 00 48 83 ?? 01 48 83 ?? 04 75 ?? 8a [0-4] 8a ?? ?? ?? c0 ?? 02 [0-1] 8b ?? c0 ?? 04 [0-2] 03 0a ?? 88}  //weight: 30, accuracy: Low
        $x_10_2 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_3 = {fd ff ff 7f 74 ?? 49 83 ?? 01 48 83 ?? 01 49 8b ?? 75 ?? eb 30 00 47 0f ?? ?? ?? 66 45 ?? ?? 74 ?? 66 44 ?? ?? 48 83 ?? 02 4c ?? ?? ff 49 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_PD_2147766620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.PD"
        threat_id = "2147766620"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 80 0a 00 00 00 c6 45 84 5f c6 45 85 64 c6 45 86 7a c6 45 87 6b c6 45 88 69 c6 45 89 61 c6 45 8a 2a c6 45 8b 4e}  //weight: 10, accuracy: High
        $x_10_2 = {45 8b c6 c6 45 ?? 46 c6 45 ?? 5b c6 45 ?? 46 c6 45 ?? 7d c6 45 ?? 5a c6 45 ?? 5d c6 45 ?? 40 c6 45 ?? 70 c6 45 ?? 46 c6 45 ?? 5d c6 45 ?? 42 c6 45 ?? 51 c6 45 ?? 46}  //weight: 10, accuracy: Low
        $x_10_3 = {41 8b d0 c6 45 ?? 72 c6 45 ?? 78 c6 45 ?? 56 c6 45 ?? 69 c6 45 ?? 70 c6 45 ?? 69 c6 45 ?? 65 c6 45 ?? 77}  //weight: 10, accuracy: Low
        $x_1_4 = {43 a1 44 a1 45 a1 46 a1 47 a1 48 a1 49 a1 4a a1 4d a1 4e a1 50 a1 51 a1 52 a1 53 a1 54 a1 55 a1 43 9d 43 9d}  //weight: 1, accuracy: High
        $x_1_5 = {c4 a2 c5 a2 c6 a2 c7 a2 c8 a2 c9 a2 d2 a2}  //weight: 1, accuracy: High
        $x_1_6 = {06 a3 04 a3 05 a3 08 a3 03 a3 0d a3 0c a3 0e a3 4b 9d 4e 9d 50 9d 53 9d 56 9d 58 9d 84 9d}  //weight: 1, accuracy: High
        $x_1_7 = {80 32 4e 03 cb 48 03 d3 41 3b cf 72 f3}  //weight: 1, accuracy: High
        $x_1_8 = {0f be 4c 15 ?? 83 e9 04 88 4c 15 ?? 48 ff c2 48 83 fa}  //weight: 1, accuracy: Low
        $x_1_9 = {42 0f be 54 05 ?? 8b 45 ?? 0f be c8 8b c2 33 c1 42 88 44 05 ?? 49 ff c0 49 83 f8}  //weight: 1, accuracy: Low
        $x_1_10 = {0f be 4c 14 ?? 83 e9 06 88 4c 14 ?? 48 ff c2 48 83 fa}  //weight: 1, accuracy: Low
        $x_1_11 = {33 d2 33 c9 41 b8 3f 00 0f 00 ff 15 1a 45 01 00}  //weight: 1, accuracy: High
        $x_1_12 = {41 b8 ff 01 0f 00 48 8d 54 24 20 48 8b cf ff 15 c3 44 01 00}  //weight: 1, accuracy: High
        $x_1_13 = {ba 0c 28 22 00}  //weight: 1, accuracy: High
        $x_1_14 = {ba 14 28 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_AB_2147766644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.AB!MTB"
        threat_id = "2147766644"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BotLoader" wide //weight: 10
        $x_10_2 = "Global\\TrickBot" wide //weight: 10
        $x_1_3 = "wtfismyip.com" wide //weight: 1
        $x_1_4 = "icanhazip.com" wide //weight: 1
        $x_1_5 = "svchost.exe" wide //weight: 1
        $x_1_6 = "<moduleconfig>*</moduleconfig>" wide //weight: 1
        $x_5_7 = "client_id" wide //weight: 5
        $x_5_8 = "config.conf" wide //weight: 5
        $x_5_9 = "group_tag" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_ZZ_2147766671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.ZZ"
        threat_id = "2147766671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 48 8b f1 48 33 c0 68 58 02 00 00 59 50 e2 fd 48 8b c7 57 48 8b ec 48 05 0b 30 00 00 48 89 45 08 48 89 75 40 68 f0 ff 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_ZY_2147766673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.ZY"
        threat_id = "2147766673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 f8 48 3b 45 f0 73 28 48 8b 45 18 0f b6 00 66 98 48 8b 55 f8 66 89 02 48 8b 45 18 0f b6 00 84 c0 74 0c 48 83 45 f8 02 48 83 45 18 01 eb cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_ZX_2147766674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.ZX"
        threat_id = "2147766674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FAILED to send PASSWORDS to DPost" ascii //weight: 1
        $x_1_2 = "DPST" ascii //weight: 1
        $x_1_3 = "FAILED to send HISTORY to DPost" ascii //weight: 1
        $x_1_4 = "FAILED to send autofill data to DPost" ascii //weight: 1
        $x_1_5 = "FAILED to send HTTP POST intercept to DPost" ascii //weight: 1
        $x_1_6 = "Successfully sent PASSWORDS to DPost" ascii //weight: 1
        $x_1_7 = "Successfully sent HISTORY to DPost" ascii //weight: 1
        $x_1_8 = "Successfully sent autofill data to DPost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_ZW_2147766679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.ZW"
        threat_id = "2147766679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegGetValueW" ascii //weight: 1
        $x_1_2 = "<general>" wide //weight: 1
        $x_1_3 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_4 = "SELECT * FROM Win32_Processor" wide //weight: 1
        $x_1_5 = "<cpu>%s</cpu>" wide //weight: 1
        $x_1_6 = "SELECT * FROM Win32_ComputerSystem" wide //weight: 1
        $x_1_7 = "<ram>%s</ram>" wide //weight: 1
        $x_1_8 = "<user>%s</user>" wide //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide //weight: 1
        $x_1_10 = "<program>%s</program>" wide //weight: 1
        $x_1_11 = "<service>%s</service>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_SS_2147766715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SS!MTB"
        threat_id = "2147766715"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dllor.dll" ascii //weight: 1
        $x_1_2 = "bEjvvgF7zLSVe7I" ascii //weight: 1
        $x_1_3 = "SKe1E7e1BJnWQG" ascii //weight: 1
        $x_1_4 = "0qjqOSdonoe2dLUW" ascii //weight: 1
        $x_1_5 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_A_2147766733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.A!mod"
        threat_id = "2147766733"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "mod: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 4c ?? ?? b8 09 04 02 81 83 e9 ?? 44 6b c1 ?? 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 b8 09 04 02 81 41 83 c0 7f 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 46 88 44 ?? ?? 49 ff ?? 49 83 ?? ?? 72 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {72 64 70 73 63 61 6e 2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_SE_2147766742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SE"
        threat_id = "2147766742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 48 89 56 70 4c 89 46 78 4c 89 8e 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b c9 48 89 8e 88 00 00 00 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 4c 89 8e 80 00 00 00 8b c9}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 8e 88 00 00 00 48 89 56 70 4c 89 46 78 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Trickbot_SV_2147766791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.SV!MTB"
        threat_id = "2147766791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c4 48 89 58 ?? 48 89 70 ?? 48 89 78 ?? 55 41 54 41 55 41 56 41 57 48 8d a8 ?? ?? ?? ?? 48 81 ec ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 33 c4 48 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 db c6 85 ?? ?? ?? ?? ?? 33 c0 c6 85 ?? ?? ?? ?? ?? 44 8b c3 c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? 44 8d 6b 01 c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 42 0f be ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f be c8 8b c2 33 c1 42 88 84 ?? ?? ?? ?? ?? 4d 03 c5 49 83 f8 0c 72}  //weight: 5, accuracy: Low
        $x_1_2 = "MailClient.dll" ascii //weight: 1
        $x_1_3 = "MoveLeft" ascii //weight: 1
        $x_1_4 = "Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_BM_2147767735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.BM!MSR"
        threat_id = "2147767735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1QDQ7ut(klVKin@CISRe_Vu3YX^bKUDDTDhJUjMMZA&<mSr>fEj&>NGGNuf" ascii //weight: 1
        $x_1_2 = "\\WindowsSDK7-Samples-master\\WindowsSDK7-Samples-master\\com\\administration\\spy\\x64\\Release\\ComSpy.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_CK_2147788491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.CK!MTB"
        threat_id = "2147788491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 48 60 73 65 00 b9 f8 2a 00 00 ff 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 85 c0 74 eb c7 44 24 ?? 53 65 6c 65 8b 44 24 ?? ff c0 89 44 24 ?? c7 44 24 ?? 57 61 6e 74 8b 44 24 ?? ff c8}  //weight: 1, accuracy: Low
        $x_1_2 = "Release" ascii //weight: 1
        $x_1_3 = "FreeBuffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_CH_2147788492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.CH!MTB"
        threat_id = "2147788492"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d0 b9 03 00 00 00 48 8b d8 c7 ?? 45 6e 74 65 c7 ?? ?? 72 20 74 6f c7 ?? ?? 20 43 6f 6e c7 ?? ?? 74 72 6f 6c 66 c7 ?? ?? 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d8 c7 ?? 4d 6f 64 75 c7 ?? ?? 6c 65 20 68 c7 ?? ?? 61 6e 64 6c c7 ?? ?? 65 20 30 78 c7 ?? ?? 25 30 38 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_STL_2147796959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.STL"
        threat_id = "2147796959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 6c 69 66 65 2f 76 69 76 69 64 00 [0-64] 4c 4c 44 20 50 44 42 2e 01 00 00 00 63 6f 72 65 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_1_2 = {5f 78 36 34 5f 72 75 6e 64 6c 6c 33 32 2e 64 6c 6c [0-32] 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_1_3 = {48 b8 f9 99 e8 9b f9 9d 9e 9f}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 97 98 8c 91 65 6d 31 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Trickbot_AC_2147798314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.AC!MTB"
        threat_id = "2147798314"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "master secret" ascii //weight: 3
        $x_3_2 = "1.3.6.1.5.5.7.3.1" ascii //weight: 3
        $x_3_3 = "x45bc719fe01.13" ascii //weight: 3
        $x_3_4 = "AddVectoredExceptionHandler" ascii //weight: 3
        $x_3_5 = "GetProcessAffinityMask" ascii //weight: 3
        $x_3_6 = "PRI * HTTP/2.0" ascii //weight: 3
        $x_3_7 = "client finished" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_RPU_2147840624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.RPU!MTB"
        threat_id = "2147840624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 30 02 48 8d 52 01 ff c1 83 f9 1e 72 f2 45 33 c9 4c 89 6c 24 30 44 89 6c 24 28 48 8d 4c 24 40 ba 00 00 00 80 c7 44 24 20 03 00 00 00 45 8d 41 01 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_MA_2147848911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.MA!MTB"
        threat_id = "2147848911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 89 c1 83 c1 01 89 4c 24 20 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 0c 08 8b 44 24 28 89 c2 83 c2 01 89 54 24 28 48 98 88 4c 04 1c 83 7c 24 28 04 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 44 24 1c c1 e0 02 0f be 4c 24 1d 83 e1 30 c1 f9 04 01 c8 88 44 24 19 0f be 44 24 1d 83 e0 0f c1 e0 04 0f be 4c 24 1e 83 e1 3c c1 f9 02 01 c8 88 44 24 1a 0f be 44 24 1e 83 e0 03 c1 e0 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickbot_RPX_2147888200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickbot.RPX!MTB"
        threat_id = "2147888200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4c 24 38 66 44 89 64 24 40 41 bc 01 00 00 00 c7 44 24 44 e1 07 01 00 c7 44 24 54 a0 05 00 00 66 44 89 64 24 48 44 89 64 24 58 44 89 64 24 60 66 44 89 64 24 64 48 8b 01 48 8d 54 24 40 ff 50 18 85 c0 0f 88 9d 00 00 00 48 8b 8d 88 00 00 00 66 89 5c 24 70 48 8d 54 24 70 48 8b 01 45 33 c0 ff 90 f0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

