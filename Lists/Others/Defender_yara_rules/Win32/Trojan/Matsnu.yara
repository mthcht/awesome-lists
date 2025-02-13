rule Trojan_Win32_Matsnu_A_2147652606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.gen!A"
        threat_id = "2147652606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 6e 74 6c 66 c7 85 ?? ?? ff ff 64 72}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 75 08 83 c6 18 8b 4d 0c 83 e9 18 72 72 57 51 56 e8}  //weight: 2, accuracy: High
        $x_1_3 = "cmd=key&data=%u:%u:%s" ascii //weight: 1
        $x_1_4 = {47 45 4f 3a 00 4c 4f 43 4b 3a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matsnu_B_2147660318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.gen!B"
        threat_id = "2147660318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".com/temp/a.php" ascii //weight: 1
        $x_1_2 = {5b 8b 7d 08 81 3f 4c 5a 57 21 75 06 8b 47 04}  //weight: 1, accuracy: High
        $x_1_3 = {30 d0 31 c9 b1 08 d3 ea f8 d1 d8 73 05 35 20 83 b8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matsnu_J_2147679609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.J"
        threat_id = "2147679609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3e 00 74 13 31 c0 8a 06 24 1f 8d 55 d4 01 c2 8a 02 88 07 46 47 eb e8}  //weight: 1, accuracy: High
        $x_1_2 = {73 61 6e 64 c7 45 ?? 2d 62 6f 78}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 70 72 65 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {67 65 74 3d c7 85 ?? ?? ?? ?? 72 65 70 6f c7 85 ?? ?? ?? ?? 72 74 26 74}  //weight: 1, accuracy: Low
        $x_1_5 = {49 4d 41 47 45 53 3a 00 47 45 4f 3a 00 4c 4f 43 4b 3a 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 52 4c 53 3a 00 45 58 45 43 55 54 45 3a 00 4b 49 4c 4c 3a 00}  //weight: 1, accuracy: High
        $x_1_7 = "&ver=%s&ltype=ml&%s" ascii //weight: 1
        $x_1_8 = {67 65 74 3d c7 45 ?? 67 65 74 73 c7 45 ?? 65 6e 64 65 c7 45 ?? 72 73 74 6f}  //weight: 1, accuracy: Low
        $x_1_9 = {67 65 74 3d c7 85 ?? ?? ?? ?? 63 66 67 26 c7 85 ?? ?? ?? ?? 73 74 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Matsnu_L_2147682791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.L"
        threat_id = "2147682791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TASKKILL /F /FI \"USERNAME eq %s\" /FI \"PID ne %u\" /IM svchost.exe" ascii //weight: 1
        $x_1_2 = {00 45 58 45 43 44 4c 4c 3a 00}  //weight: 1, accuracy: High
        $x_2_3 = "%s?id=%s&cvr=5&ver=%s&ltype=ml&%s" ascii //weight: 2
        $x_2_4 = {00 4d 41 49 4e 45 52 46 49 4c 45 3a 00}  //weight: 2, accuracy: High
        $x_2_5 = {0f 31 31 d0 89 45 fc 31 d2 b9 ?? ?? ?? ?? f7 f1 89 c1 b8 ?? ?? ?? ?? f7 e2 89 ca 89 c1 b8 ?? ?? ?? ?? f7 e2 29 c1 31 d2 89 c8 89 4d fc b9 ?? ?? ?? ?? f7 f1 89 d0 59 5a}  //weight: 2, accuracy: Low
        $x_2_6 = {ff 75 0c ff 75 08 e8 0f 00 00 00 69 64 74 3d 25 75 26 63 6f 64 65 3d 25 75 00}  //weight: 2, accuracy: High
        $x_1_7 = "id=%s&ver=%s&cvr=%u&threadid=%u&lang=0x%04X&os=%s&%s" ascii //weight: 1
        $x_1_8 = "dlllist=%s&proclist=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matsnu_M_2147689087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.M"
        threat_id = "2147689087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s~%08x-%04x-%04x.pre" ascii //weight: 1
        $x_1_2 = "sended=%u&error=%u&exerr=%u&" ascii //weight: 1
        $x_1_3 = {e8 09 00 00 00 52 65 67 4d 6f 6e 45 76 00 6a 00 6a 01 6a 00 ff 93}  //weight: 1, accuracy: High
        $x_1_4 = {e8 0a 00 00 00 2f 25 73 3a 2a 2d 2d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matsnu_O_2147690811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.O"
        threat_id = "2147690811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MAIN%08XMUTEX" ascii //weight: 1
        $x_1_2 = {e8 05 00 00 00 2e 64 6c 6c 00 8d 95 f0 fe ff ff 52 ff 93}  //weight: 1, accuracy: High
        $x_1_3 = {e8 0a 00 00 00 2f 25 73 3a 2a 2d 2d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {30 d0 31 c9 b1 08 d3 ea f8 d1 d8 73 05 35 20 83 b8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matsnu_M_2147691132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.M!!Matsnu.gen!A"
        threat_id = "2147691132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        info = "Matsnu: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "dlllist=%s&proclist=%s" ascii //weight: 2
        $x_3_2 = "id=%s&mynum=%u&ver=%s&cvr=%u&threadid=%u" ascii //weight: 3
        $x_3_3 = "&lang=0x%04X&os=%s&crcblw=%08x&%s" ascii //weight: 3
        $x_1_4 = "GET=%s&AES=%s" ascii //weight: 1
        $x_1_5 = "idt=%u&code=%u" ascii //weight: 1
        $x_1_6 = "get=raport" ascii //weight: 1
        $x_1_7 = "get=sysinfo" ascii //weight: 1
        $x_1_8 = {00 45 4e 44 44 44 44 44 00}  //weight: 1, accuracy: High
        $x_1_9 = {50 4f 53 54 ?? ?? ?? 00 ?? ?? ?? 48 54 54 50}  //weight: 1, accuracy: Low
        $x_1_10 = {30 32 64 20 ?? ?? ?? ?? ?? ?? ?? 47 4d ?? ?? ?? ?? ff ff 54}  //weight: 1, accuracy: Low
        $x_1_11 = {ff 52 43 50 4b}  //weight: 1, accuracy: High
        $x_1_12 = {43 4f 4d 50 ?? ?? ?? 4c 45 54 45}  //weight: 1, accuracy: Low
        $x_1_13 = {e8 11 00 00 00 43 55 52 52 45 4e 54 25 30 38 58 4d 55 54 45 58 00}  //weight: 1, accuracy: High
        $x_2_14 = {e8 05 00 00 00 2e 64 6c 6c 00 8d 95 f0 fe ff ff 52 ff 93}  //weight: 2, accuracy: High
        $x_2_15 = {e8 0a 00 00 00 2f 25 73 3a 2a 2d 2d 25 73 00}  //weight: 2, accuracy: High
        $x_1_16 = {30 d0 31 c9 b1 08 d3 ea f8 d1 d8 73 05 35 20 83 b8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matsnu_M_2147691132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.M!!Matsnu.gen!A"
        threat_id = "2147691132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        info = "Matsnu: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=config&upgrade=%u&crashed=%u" ascii //weight: 1
        $x_1_2 = "=getsenderstocheck" ascii //weight: 1
        $x_1_3 = "=mainbody&hash=%s&task=%u" ascii //weight: 1
        $x_1_4 = "=report&task=%u&threadid=%u" ascii //weight: 1
        $x_1_5 = "=%s&ver=%s&cvr=%u&stth=%u:%u&threadid=%u&lang=0x%04X&os=%s&%s" ascii //weight: 1
        $x_1_6 = "=%u&get=sendercheckreport&threadid=%u" ascii //weight: 1
        $x_1_7 = "sended=%u&error=%u&exerr=%u&time=%u&result=%s&table=%s&remark=%s" ascii //weight: 1
        $x_1_8 = "thid=%u&count=%u&error=%u&time=%u&real=%u&senders=%s&table=%s&remark=%s&nosmtp=%s" ascii //weight: 1
        $x_1_9 = "{Let_uniq_id=" ascii //weight: 1
        $x_1_10 = "{Let_one_id=" ascii //weight: 1
        $x_1_11 = "/F /FI \"USERNAME eq %s\" /FI \"PID ne %u\" /IM dllhost.exe" ascii //weight: 1
        $x_1_12 = {50 4f 53 54 c6 45 ?? 00 c7 45 ?? 48 54 54 50 c7 45 ?? 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_13 = {e8 0f 00 00 00 3d 3f 75 74 66 2d 38 3f ?? 3f 25 73 3f 3d 00}  //weight: 1, accuracy: Low
        $x_1_14 = {45 48 4c 4f 66 c7 45 ?? 20 25 c6 45 ?? 73 c6 45 ?? 0d c6 45 ?? 0a c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_15 = {53 54 41 52 c7 45 ?? 54 54 4c 53 c6 45 ?? 0d c6 45 ?? 0a c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_16 = {5b 63 6f 6d 66 c7 45 ?? 61 5d c6 45 ?? 00 c7 45 ?? 5b 64 64 6f 66 c7 45 ?? 74 5d c6 45 ?? 00 c7 45 ?? 5b 64 6f 67}  //weight: 1, accuracy: Low
        $x_1_17 = {50 4b 66 c7 85 ?? ?? ff ff 50 4b 66 c7 85 ?? ?? ff ff 03 04 66 c7 85 ?? ?? ff ff 01 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Matsnu_W_2147706270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.W"
        threat_id = "2147706270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 66 8b f6 4e 46 66 8b f6 4e 46 66 8b f6 4e 46 8b 91 b8 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 49 41 49 41 4e 46 49 41 49 41 4e 46 b8 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matsnu_R_2147711433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.R"
        threat_id = "2147711433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "dlllist=%s&proclist=%s" ascii //weight: 2
        $x_3_2 = "id=%s&mynum=%u&ver=%s&cvr=%u&threadid=%u" ascii //weight: 3
        $x_3_3 = "&lang=0x%04X&os=%s&crcblw=%08x&%s" ascii //weight: 3
        $x_1_4 = "GET=%s&AES=%s" ascii //weight: 1
        $x_1_5 = "idt=%u&code=%u" ascii //weight: 1
        $x_1_6 = "get=raport" ascii //weight: 1
        $x_1_7 = "get=sysinfo" ascii //weight: 1
        $x_1_8 = {00 45 4e 44 44 44 44 44 00}  //weight: 1, accuracy: High
        $x_1_9 = {50 4f 53 54 ?? ?? ?? 00 ?? ?? ?? 48 54 54 50}  //weight: 1, accuracy: Low
        $x_1_10 = {30 32 64 20 ?? ?? ?? ?? ?? ?? ?? 47 4d ?? ?? ?? ?? ff ff 54}  //weight: 1, accuracy: Low
        $x_1_11 = {ff 52 43 50 4b}  //weight: 1, accuracy: High
        $x_1_12 = {43 4f 4d 50 ?? ?? ?? 4c 45 54 45}  //weight: 1, accuracy: Low
        $x_1_13 = {e8 11 00 00 00 43 55 52 52 45 4e 54 25 30 38 58 4d 55 54 45 58 00}  //weight: 1, accuracy: High
        $x_2_14 = {e8 05 00 00 00 2e 64 6c 6c 00 8d 95 f0 fe ff ff 52 ff 93}  //weight: 2, accuracy: High
        $x_2_15 = {e8 0a 00 00 00 2f 25 73 3a 2a 2d 2d 25 73 00}  //weight: 2, accuracy: High
        $x_1_16 = {30 d0 31 c9 b1 08 d3 ea f8 d1 d8 73 05 35 20 83 b8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matsnu_SIB_2147798811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matsnu.SIB!MTB"
        threat_id = "2147798811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matsnu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 40 00 00 00 [0-16] 50 [0-5] b9 00 30 00 00 [0-5] 51 ff 75 14 33 c0 [0-42] 50 [0-16] ff 15 ?? ?? ?? ?? [0-5] 8b f8 89 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 88 08 [0-5] 83 c7 01 [0-16] 89 35 ?? ?? ?? ?? [0-8] bb f1 28 41 00 [0-16] 29 1d 02 [0-16] 8a 0e [0-16] 46 [0-16] 80 c1 ?? [0-10] c0 c9 ?? [0-16] fe c9 [0-10] 32 0d ?? ?? ?? ?? [0-5] c0 c1 ?? [0-10] fe c1 [0-16] c0 c9 ?? [0-10] c0 c9 ?? [0-5] c0 c1 ?? [0-16] c0 c1 ?? [0-10] 80 c1 ?? [0-16] fe c9 [0-5] fe c9 [0-16] fe c1 [0-10] fe c1 [0-16] fe c9 [0-16] c0 c9 ?? [0-16] 8b c7 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

