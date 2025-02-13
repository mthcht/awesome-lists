rule Trojan_Win32_Filisto_A_2147717647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filisto.A!dha"
        threat_id = "2147717647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 0f eb 07 8a 44 0a ff 30 04 0a 4a 75 f6 80 31 ad c3}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 0f 85 97 00 00 00 39 85 f0 02 00 00 74 59 68 06 02 00 00 50 66 89 85 f8 fd ff ff 8d 85 fa fd ff ff 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {75 2e 81 ec e4 02 00 00 8d 75 08 b9 b9 00 00 00 8b fc f3 a5 8b 8c 24 fc 02 00 00 8b d3 e8}  //weight: 1, accuracy: High
        $x_1_4 = {eb 24 8d 45 f8 50 ff 75 08 6a 00 6a 00 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 57 8b f0 ff 15 ?? ?? ?? ?? 85 f6 74 17 8d 45 fc 50 e8 ?? ?? ?? ?? 8b f8 85 ff 75 cd}  //weight: 1, accuracy: Low
        $x_1_5 = "\\00EVSETUP.TMP" wide //weight: 1
        $x_1_6 = "\\TS_FB56.tmp" wide //weight: 1
        $x_1_7 = "AutoConfigURL" wide //weight: 1
        $x_1_8 = "0x04, firefox proxy %s:%d too long" wide //weight: 1
        $x_1_9 = "/?%s=%s&%s=%d&%s=%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Filisto_DF_2147748463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filisto.DF!MTB"
        threat_id = "2147748463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c9 c3 80 31 ?? 33 c0 40 8a 54 08 ?? 30 14 08 40 3d ?? ?? ?? ?? 7c f1 c3 eb 07 8a 54 08 ?? 30 14 08 48 85 c0 7f f4 80 31 ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 [0-6] c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? 8d 7d ?? aa 6a ?? 58 8d 4d ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filisto_B_2147751733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filisto.B!dha"
        threat_id = "2147751733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{A872638D-DC2B9B23}" ascii //weight: 1
        $x_1_2 = "{78811C7B-AC3A8201}" ascii //weight: 1
        $x_1_3 = "{IO4A912X-CIY43VWR}" ascii //weight: 1
        $x_1_4 = "{73ABDC3D-7A30-425B-A93D-9B1C814AEC9A}" wide //weight: 1
        $x_1_5 = "{B06E11AD-716E332A}" ascii //weight: 1
        $x_1_6 = "{2643B32C-9718-44B6-B814-381BA6F29BAC}" ascii //weight: 1
        $x_1_7 = "{B6E56F0C-F1B75B7F}" ascii //weight: 1
        $x_1_8 = "{B66270F0-GJHGHB23}" ascii //weight: 1
        $x_1_9 = "{CBDB119C-C577-4928-99D4-F12E97C3A092}" ascii //weight: 1
        $x_1_10 = "{6B44E29D-DCC2403C}" ascii //weight: 1
        $x_1_11 = "{DDC64072-CF794486}" ascii //weight: 1
        $x_1_12 = "{B66270F0-CADCBE85}" ascii //weight: 1
        $x_1_13 = "{48D4A606-31C4-4E5A-9003-21F0CF9B6C29}" wide //weight: 1
        $x_1_14 = "{9E1EFAC5-AF274E4C}" ascii //weight: 1
        $x_1_15 = "{872F26B7-D6758EBD}" ascii //weight: 1
        $x_1_16 = "{CD8A6F16-CBD94BCE}" ascii //weight: 1
        $x_1_17 = "{41599890-8A18-4200-BE3C-B9B179BFBC5A}" ascii //weight: 1
        $x_1_18 = "{D4Q7S59V-E0H82FSR}" ascii //weight: 1
        $x_1_19 = "C{Qj;8V5[%9Sv<E/!m>Bew|tjVx?Nf#c" ascii //weight: 1
        $x_1_20 = "CUhYXdL)[DQHGM4p!]90}5.Yj$>(&/sH" ascii //weight: 1
        $x_1_21 = "Cm})2&!j[V&p*njS!EnYqWSBj|WHZFB?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Filisto_H_2147912108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filisto.H!dha"
        threat_id = "2147912108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "runexe 1.exe" ascii //weight: 3
        $x_2_2 = "8clmo(3{<LUVXo-!w4DEGXrjf.]|}Ga" ascii //weight: 2
        $x_1_3 = "0x01, set Param failed!" ascii //weight: 1
        $x_1_4 = "0x01, %s login by %s failed." ascii //weight: 1
        $x_1_5 = "0x00, Set Config failed." ascii //weight: 1
        $x_1_6 = "0x01, exec %d success." ascii //weight: 1
        $x_1_7 = "0x01, SSD failed %d." ascii //weight: 1
        $x_1_8 = "0x04, CEPHL failed" wide //weight: 1
        $x_1_9 = "0x04, RD not enough, %d, " wide //weight: 1
        $x_1_10 = "0x00, miss server config." ascii //weight: 1
        $x_1_11 = "0x06, delay %d." ascii //weight: 1
        $x_1_12 = "0x04, send %d success." ascii //weight: 1
        $x_1_13 = "Recv UDD Response Fail!" ascii //weight: 1
        $x_1_14 = "Online Fail!Wait for %d mins" ascii //weight: 1
        $x_1_15 = "Execute order :%s Failed! - %d" ascii //weight: 1
        $x_1_16 = "Encrypt1 Fail!" ascii //weight: 1
        $x_1_17 = "0x3F TCT-%d..." ascii //weight: 1
        $x_1_18 = "0x07 CT-%d FAIL." ascii //weight: 1
        $x_1_19 = "0x06 OF WF%dm" ascii //weight: 1
        $x_1_20 = "0x3E SLEP-%d m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Filisto_I_2147912109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filisto.I!dha"
        threat_id = "2147912109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 81 c9 00 ff ff ff 41 0f b6 c1 8b 4d fc 89 45 08 8a 04 30 88 01 8b 45 08 88 1c 30 8d 42 01 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 c3 89 45 08 8a 04 30 88 04 31 8b 45 08 88 14 30 0f b6 0c 31 0f b6 c2 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41}  //weight: 1, accuracy: High
        $x_1_3 = {89 47 14 c7 47 20 ?? ?? ?? ?? c7 47 24 ?? ?? ?? ?? c7 47 28 ?? ?? ?? ?? c7 47 2c ?? ?? ?? ?? [0-7] 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

