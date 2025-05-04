rule Trojan_Win32_BlackMoon_DH_2147824222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.DH!MTB"
        threat_id = "2147824222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 39 84 d2 7d 0b 66 8b 14 39 66 89 14 01 41 eb 0f 81 e2 ff 00 00 00 8a 92 04 9b 44 00 88 14 01 41 3b ce 72}  //weight: 1, accuracy: High
        $x_1_2 = {ff 33 8b 5d 80 ff 33 8b 5d 84 ff 33 8b 5d 88 ff 33 8b 5d 8c ff 33 8b 5d 90 ff 33 8b 5d 94 ff 33 8b 5d 98 ff 33 8b 5d 9c ff 33 b9 09 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = "hutao.pxxht.icu/download.exe" ascii //weight: 1
        $x_1_4 = "stfu1.pixxvv.club" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_DL_2147836468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.DL!MTB"
        threat_id = "2147836468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 39 06 19 06 08 23 06 10 08 30 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_CF_2147843097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.CF!MTB"
        threat_id = "2147843097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e0 02 03 d8 89 5d f0 6a 01 b8 2d 64 4b 00 89 45 ec 8d 45 ec 50 ff 75 f0 e8 [0-4] 8b 5d ec 85 db 74}  //weight: 5, accuracy: Low
        $x_1_2 = "blackievirus.com/smtp.txt" ascii //weight: 1
        $x_1_3 = "[autorun]" ascii //weight: 1
        $x_1_4 = "shellexecute=" ascii //weight: 1
        $x_1_5 = "MySelf.exe" ascii //weight: 1
        $x_1_6 = "www.blackievirus.com/text.txt" ascii //weight: 1
        $x_1_7 = "shutdown -s -t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_DAO_2147851319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.DAO!MTB"
        threat_id = "2147851319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c8 b7 a3 ac d4 ad d2 f2 bf c9 c4 dc ca c7 a3 ba 00 bc c7 b4 ed c3 dc c2 eb a3 bb ce aa c7 f8 b7 d6 b4 f3 d0 a1 d0 b4 a3 bb ce b4 bf aa c6 f4 d0 a1 bc fc c5 cc a1 a3}  //weight: 1, accuracy: High
        $x_1_2 = {d1 c9 e8 d6 c3 c3 dc b1 a3 ce ca cc e2 00 c3 dc b1 a3 ce ca cc e2 00 d3 c9 d3 da c4 fa b3 a4 c6 da c3 bb d3 d0 d1 e9 d6 a4 c3 dc b1 a3 a3 ac ce aa c1 cb c8 b7 b1 a3 c4 fa b5}  //weight: 1, accuracy: High
        $x_1_3 = {b5 e7 d0 c5 be c5 00 b5 e7 d0 c5 ca ae 00 b5 e7 d0 c5 ca ae d2 bb 00 cd f8 cd a8 ce e5 00 b5 e7 d0 c5 ca ae b6 fe 00 b5 e7 d0 c5 ca ae cb c4 00 b5 e7 d0 c5 ca ae c8 fd}  //weight: 1, accuracy: High
        $x_1_4 = {de ce b7 cf c8 b7 e6 00 b2 c3 be f6 d6 ae b5 d8 00 ba da c9 ab c3 b5 b9 e5 00 b0 b5 d3 b0 b5 ba 00 cb a1 c8 f0 c2 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_DW_2147888226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.DW!MTB"
        threat_id = "2147888226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 78 58 23 ea 5b 23 93 b7 5e 1a 55 15 b1 57 f0 b8 89 4d 78 64 a8 36 51 2d de be af 0b 14 e8 51}  //weight: 2, accuracy: High
        $x_2_2 = {d1 02 a8 4b 2f 38 08 92 33 77 e1 67 04 fb eb}  //weight: 2, accuracy: High
        $x_1_3 = "C:\\ezdun.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_DX_2147888233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.DX!MTB"
        threat_id = "2147888233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B8 AB AA AA 2A F7 E9 D1 FA 8B CA C1 E9 1F 03 CA 33 DB 85 C9 7E 6F 33 " ascii //weight: 1
        $x_1_2 = "8B 4C 24 04 2B D0 C1 FA 02 3B CA 73 04 8B 04 88 C3 33 C0 C3 CC" ascii //weight: 1
        $x_1_3 = "8D 54 24 08 52 89 44 24 0C 8D 44 24 14 50" ascii //weight: 1
        $x_1_4 = "51 56 8B F1 33 C0 89 74 24 04 88 46 04 89 46 08 8D 4E 0C" ascii //weight: 1
        $x_1_5 = "89 44 24 14 89 5C 24 44 89 5C 24 48 89 5C 24 4C" ascii //weight: 1
        $x_1_6 = "85 C9 74 05 8B 01 FF 60 24 32 C0" ascii //weight: 1
        $x_1_7 = "DINGPADDINGXXPADDINGPADDINGXXPADDINGkhy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_DT_2147889134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.DT!MTB"
        threat_id = "2147889134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Selfdrawing.exe" ascii //weight: 2
        $x_2_2 = "dat\\bin.dat" ascii //weight: 2
        $x_1_3 = "k33L35j7b8cYL83b9u8fIzQV" ascii //weight: 1
        $x_1_4 = "VfTpwvu8XwfwPpK737H148qU" ascii //weight: 1
        $x_1_5 = "eee.wxhuajia.com" ascii //weight: 1
        $x_1_6 = "miaosha.4jiasu.com" ascii //weight: 1
        $x_1_7 = "ms.gomkk.com" ascii //weight: 1
        $x_1_8 = "Eu0lUHCqTXJyZ/DYlJeKxokW7NbtyFKn3B4HUYI7l2qxWZ6jDoW3zrBcJuF41D2uMLBMV3E" ascii //weight: 1
        $x_1_9 = "3f3oPs4HTHzmVkUu5tQF156YLOiSR5EsnTM4oAsjUCtoLzjsZxZs2FNPSroGc" ascii //weight: 1
        $x_1_10 = "4D9DFB9EA4E5EA02BE8FB389B5CDD0A33CA4E593" ascii //weight: 1
        $x_1_11 = "4FB93FEF443746520F7D0798D387102457B846F0D3" ascii //weight: 1
        $x_1_12 = "99ee59209b1d69c24bb3a11f971cb83c1d919451a" ascii //weight: 1
        $x_1_13 = "8D387102457B8467E46D5A06DF1A61C71603BF8C1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BlackMoon_GMH_2147889162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GMH!MTB"
        threat_id = "2147889162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hlMemhrtuahteVihlocahZwAl" ascii //weight: 1
        $x_1_2 = "dujkZAU47ZF" ascii //weight: 1
        $x_1_3 = "\\Nop-A.sys" ascii //weight: 1
        $x_1_4 = "BlackMoon RunTime Error" ascii //weight: 1
        $x_1_5 = "dujkZDN12ZF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_AB_2147901071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.AB!MTB"
        threat_id = "2147901071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 0f b6 40 02 85 c0 75 27 64 a1 30 00 00 00 8b 40 68 83 e0 70 85 c0 75 17 64 a1 30 00 00 00 8b 40 18 83 78 0c 02 75 08 83 78 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASH_2147902326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASH!MTB"
        threat_id = "2147902326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "83 7D E8 10 8B 45 D4 C7 45 FC 08 00 00 00" ascii //weight: 1
        $x_1_2 = "@8B 48 F4 85 C9 8B CE 74 2C" ascii //weight: 1
        $x_1_3 = "C6 45 FC 04 72 05 8B 40 04 EB 03" ascii //weight: 1
        $x_1_4 = "logindlg.dll" ascii //weight: 1
        $x_1_5 = "14.18.141.27:33355/lcy.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GMC_2147904765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GMC!MTB"
        threat_id = "2147904765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {04 41 00 db 04 41 00 b7 04 41 00 c3 04 41 00 cf 04 41 00 8b 44 24 08 85 c0 74 07 50 e8 32 39 00 00 59 c3}  //weight: 10, accuracy: High
        $x_1_2 = "C:\\TEMP\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_NN_2147908383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.NN!MTB"
        threat_id = "2147908383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 69 72 63 38 66 63 6c 34 72 72 38 39 34 66 32 75 72 35 ?? ?? ?? ?? 37 65 30 37 37 37 35 ?? ?? ?? ?? 6b 6e 71 36 38 77 37 38 6e 68 62 65 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_Z_2147911260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.Z!MTB"
        threat_id = "2147911260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 03 83 c3 ?? 8b 73 ?? 89 04 ?? 89 fa 89 f8 0f b6 e8 c1 ea ?? 89 f0 8b 94}  //weight: 2, accuracy: Low
        $x_2_2 = "BlackMoon RunTime Error:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGE_2147911887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGE!MTB"
        threat_id = "2147911887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 06 00 00 00 e8 ?? ?? ?? 00 83 c4 04 89 45 f8 89 65 f0 ff 75 f8 ff 15 [0-7] 90 39 65 f0 74}  //weight: 2, accuracy: Low
        $x_2_2 = {41 51 50 3b c8 0f 8f 26 00 00 00 89 65 f0 ff 75 f8 ff 15 [0-7] 90 39 65 f0 74}  //weight: 2, accuracy: Low
        $x_1_3 = "122.224.32.8:79/hosts/myhosts.txt.txt" ascii //weight: 1
        $x_1_4 = "blackmoon" ascii //weight: 1
        $x_1_5 = "5B5252460B08D3B282C37E5E7A460E18" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGK_2147912174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGK!MTB"
        threat_id = "2147912174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 b8 32 63 47 00 89 45 f4 8d 45 f4 50 6a 01 b8 3c 63 47 00 89 45 f0 8d 45 f0 50 8d 45 fc 50 8b 04 24 8b 00 8b 00 ff 90 e0 00 00 00 8b 5d f0 85 db}  //weight: 5, accuracy: High
        $x_2_2 = {83 c4 04 6a 00 6a 00 6a 00 68 31 00 01 00 6a 00 ff 75 d0 68 02 00 00 00 bb 90 09 00 00 e8}  //weight: 2, accuracy: High
        $x_2_3 = {68 25 00 00 00 68 15 4d 05 04 68 06 00 00 00 e8 ?? ?? 04 00 83 c4 0c e9}  //weight: 2, accuracy: Low
        $x_1_4 = "BlackMoon RunTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGK_2147912174_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGK!MTB"
        threat_id = "2147912174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 4c 24 10 51 6a 00 50 52 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b 54 24 0c 33 c9 85 c0 0f 95 c1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 49 0c 33 c0 83 fe 05 55 0f 95 c0 48 57 25 ?? ?? ?? 00 52 51 50 6a 00 ff 15 ?? ?? ?? 00 5f 5e 5d c3}  //weight: 2, accuracy: Low
        $x_2_3 = {68 84 03 00 00 b8 ?? ?? ?? 00 89 45 fc 8d 45 fc 50 ff 35}  //weight: 2, accuracy: Low
        $x_1_4 = "blackmoon" ascii //weight: 1
        $x_1_5 = "@8wfwfewfwfw" ascii //weight: 1
        $x_1_6 = "\\cfsv.ini" ascii //weight: 1
        $x_1_7 = "waqiang.com/index.php/url/shorten" ascii //weight: 1
        $x_1_8 = "89875538562" ascii //weight: 1
        $x_1_9 = "nb.cdygby.com" ascii //weight: 1
        $x_1_10 = "sgw3ug232gg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGL_2147912257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGL!MTB"
        threat_id = "2147912257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 01 00 00 00 bb dc 09 00 00 e8 ?? ?? ?? 00 83 c4 10 89 45 f8 89 65 f4 68 00 00 00 00 68 00 00 00 00 ff 75 0c ff 75 f8 68 00 00 00 00 68 00 00 00 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = {83 c4 04 ff 75 dc ff 75 e4 ff 75 e8 68 ?? ?? ?? 00 b9 04 00 00 00 e8 ?? ?? ?? ff 83 c4 10 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = "blackmoon" ascii //weight: 1
        $x_1_4 = "b869706b42f0c202e5667f22da1c9cf5" ascii //weight: 1
        $x_1_5 = "www.mydlq.com" ascii //weight: 1
        $x_1_6 = "huanshouPHZH|null" ascii //weight: 1
        $x_1_7 = "ywgn-43D24A32DCEDCCC6AC3582B5F33DAC3F3B9A41F01A5FD268&2DE61E9E3C382E52E6FE7D6D17940668" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GXU_2147912567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GXU!MTB"
        threat_id = "2147912567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce c7 44 24 38 47 65 74 50 c7 44 24 3c 72 6f 63 41 c7 44 24 40 64 64 72 65 66 c7 44 24 44 73 73 c6 44 24 46 00 e8 ?? ?? ?? ?? 89 44 24 28 85 c0 0f 84}  //weight: 10, accuracy: Low
        $x_1_2 = "BlackMoon RunTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GLX_2147912749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GLX!MTB"
        threat_id = "2147912749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 00 da af 47 00 87 ?? ?? ?? ?? b0 47 00 27 b2 47 00 b8 ?? ?? ?? ?? b4 47 00 5f b4 47}  //weight: 10, accuracy: Low
        $x_1_2 = "BcnTp1h0dnMFdLlm" ascii //weight: 1
        $x_1_3 = "BlackMoon RunTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GLY_2147912798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GLY!MTB"
        threat_id = "2147912798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {af b3 04 00 83 ?? ?? ?? ?? 00 00 00 8b ?? ?? ?? ?? 00 55 8b ec e8 ?? ?? ?? ?? 8b e5 5d c3 55 8b ec 81 ec 04 00 00 00 89 65 fc 68 00 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "nHYbGVfGWdK" ascii //weight: 1
        $x_1_3 = "blackmoon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGJ_2147913073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGJ!MTB"
        threat_id = "2147913073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 89 65 f8 68 00 00 00 00 68 00 00 00 00 ff 75 08 ff 75 fc 68 00 00 00 00 68 00 00 00 00 33 c0 ff 15 ?? ?? ?? 10 ?? ?? 39 65 f8 74 17 68 5c 00 00 00 68 76 51 01 04 68 06 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 65 f4 68 64 00 00 00 33 c0 ff 15 ?? ?? ?? 10 ?? ?? 39 65 f4 74 17 68 e1 0a 00 00 68 97 5b 01 04 68 06 00 00 00 e8 ?? ?? 00 00 83 c4 0c eb}  //weight: 1, accuracy: Low
        $x_1_3 = "Global\\vcpkgsrvmgr" ascii //weight: 1
        $x_1_4 = "blackmoon" ascii //weight: 1
        $x_1_5 = "ppxh_c1djc" ascii //weight: 1
        $x_1_6 = "CreateMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GMT_2147913949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GMT!MTB"
        threat_id = "2147913949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 d2 48 41 d1 de 30 c1 d7 b0 57 30 27 9f 49 12 fe bd 37 01 3d e5 28 00 00 54 92 24 ff 00}  //weight: 10, accuracy: High
        $x_1_2 = "F-@A&pwd=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_RP_2147914404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.RP!MTB"
        threat_id = "2147914404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "eax ecx edx ebx esp ebp esi edi" ascii //weight: 10
        $x_10_2 = "new superhook" ascii //weight: 10
        $x_1_3 = "ChangeWindowMessageFilterEx" ascii //weight: 1
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
        $x_10_5 = "\\+\\-]+)|(THREADSTACK)(\\d*)" ascii //weight: 10
        $x_10_6 = "BlackMoon RunTime Error:" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGH_2147915101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGH!MTB"
        threat_id = "2147915101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 2c 03 8a 1c 03 88 1f 88 4d 00 8a 1f 02 d9 81 e3 ff 00 00 00 8a 0c 03 8a 1c 16 32 d9 8b 4c 24 1c 88 1c 16 46 3b f1 7c}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 04 68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 01 00 00 00 bb dc 09 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = "135 245 62 140 24 179 170 134 23" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGI_2147916255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGI!MTB"
        threat_id = "2147916255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 10 89 45 e8 68 04 00 00 80 6a 00 68 ?? ?? 41 00 68 01 00 00 00 bb dc 09 00 00 e8 ?? ?? 00 00 83 c4 10 89 45 e4 68 04 00 00 80 6a 00 68 ?? ?? 41 00 68 01 00 00 00 bb dc 09 00 00 e8}  //weight: 3, accuracy: Low
        $x_3_2 = {55 8b ec 81 ec 24 00 00 00 b8 ?? ?? ?? 00 89 45 fc 8d 45 fc 50 e8 ?? ?? ?? ff 89 45 f8 8b 5d fc 85 db 74}  //weight: 3, accuracy: Low
        $x_2_3 = "135 245 62 140 24 179 170 134 23" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GXN_2147918131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GXN!MTB"
        threat_id = "2147918131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 fd 67 41 00 fd 67 41 00 98 ?? ?? ?? ?? 68 ?? ?? ?? ?? 41 00 f9 68 ?? ?? ?? ?? 41 00 78 69 41 00 66 69 41 00 78 69 41 00 a0 69 41 00 a0}  //weight: 10, accuracy: Low
        $x_1_2 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GNN_2147918868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GNN!MTB"
        threat_id = "2147918868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 5d 0c 89 03 8b 4d f4 8b 55 0c 8b 12 83 c2 08 33 c0 33 db 51 0f b6 c8 fe c1 52 8a 34 39 02 de 8a 14 3b 88 14 39 88 34 3b 02 d6 0f b6 d2 8a 14 3a 8a 0c 30 32 ca 5a 88 0c 10 40 59 e2 d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GNX_2147919139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GNX!MTB"
        threat_id = "2147919139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 d4 68 00 00 00 00 68 48 00 00 00 ff 75 e4 ff 75 d4 ff 75 fc 33 c0 ff 15 ?? ?? ?? ?? ?? ?? 68 3c 00 00 00 ff 75 e4 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_AT_2147919690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.AT!MTB"
        threat_id = "2147919690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 67 88 58 9b 06 45 1e aa 7e 40 7c 51 3b a4 c2 9e 0a c6 4c 13 06 5b 35 70 2d 48 50 00 20 ed 6d 0c 3f 2e db df dc 75 ac 95 ad b1 98 24 19 44 ?? 24 b9 33 14 99 ea 13 71 5a 5b 46 da 5a a2 c7 73 01 40 c6 05 3c 25 8b 07 a8 76 ca fe 26 0e 81 aa a2 37 22 00 8a f7 fe 47 2f 05 e9 61 af ef b8 7b b6 f6 b8 4e 6e e5 f2 a7 ff 08 00 80 d4 d9 12 d1 ba 5a 1e 8e 1d 05 45 89 cb 0e 8a c2 07 c1 e0 28 15 2a 80 4a 8b c8 79 fc b4 7f 30 78 bc 3f 09 2b 00 18}  //weight: 1, accuracy: Low
        $x_1_2 = {80 fe 3d 66 0f ab f9 f9 89 f9 66 0f bb fe 48 ff ce c1 d6 02 f8 29 d9 66 0f bc f6 48 89 e6 f5 85 d7 f9 48 81 fd a8 a7 5b 69 48 83 ef 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BlackMoon_NG_2147920700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.NG!MTB"
        threat_id = "2147920700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BlackMoon RunTime Error" ascii //weight: 2
        $x_2_2 = "8@VBScript.RegExp" ascii //weight: 2
        $x_1_3 = "202.189.7.231" ascii //weight: 1
        $x_1_4 = "eaigpuex.dll" ascii //weight: 1
        $x_1_5 = "WinHttpCrackUrl" ascii //weight: 1
        $x_1_6 = "Eai.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ASGM_2147920918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ASGM!MTB"
        threat_id = "2147920918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 b6 bc d2 00 68 00 00 00 00 68 01 20 00 00 ff 75 ec ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 f0 ff 75 f8 68 00 00 00 00 ff 75 f0 8b 5d 08 ff 33 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = {89 45 ec 68 80 a0 80 00 68 00 00 00 00 68 09 04 00 00 ff 75 ec ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "b869706b42f0c202e5667f22da1c9cf5" ascii //weight: 1
        $x_1_5 = "c3\\npc\\744\\100.c3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GNT_2147924099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GNT!MTB"
        threat_id = "2147924099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 43 5d 44 0a 53 ?? 67 00 25 3c 0b 83 37 ?? 59 b0 00 8c 1c c7 36 b7 92 04 68 01 27}  //weight: 10, accuracy: Low
        $x_1_2 = "C:\\Windows\\EncryptSynaptics.com" ascii //weight: 1
        $x_1_3 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GNT_2147924099_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GNT!MTB"
        threat_id = "2147924099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f3 22 ec 14 ae 89 0a 33 72 63 85 b2 ?? ?? ?? ?? 82 70 67 e4 11 65 a6}  //weight: 5, accuracy: Low
        $x_5_2 = {13 38 44 7d ?? 13 38 8d be ?? ?? ?? ?? 78 ?? 13 38 8c 40 c7 13 38 32 f0 5f 10 38}  //weight: 5, accuracy: Low
        $x_5_3 = {32 d8 80 f5 b9 66 0f bd c8 8b 4c 25 00 8d ad 04 00 00 00 66 3b fc 89 0c 04 66 2b c2 66 0f ab c8}  //weight: 5, accuracy: High
        $x_1_4 = "hlMemhrtuahteVihlocahZwAl" ascii //weight: 1
        $x_1_5 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BlackMoon_AGN_2147924228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.AGN!MTB"
        threat_id = "2147924228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HMTxwNSQRySOGklFVJ1rKylO07Gk|H370JTItKU7TsaT5Mi0" ascii //weight: 1
        $x_1_2 = "blackmoon" ascii //weight: 1
        $x_2_3 = "QQ_Exit_Info_Mutex_" ascii //weight: 2
        $x_2_4 = "5B3838F5-0C81-46D9-A4C0-6EA28CA3E942" ascii //weight: 2
        $x_1_5 = "{E29FFD8F-0283-4772-834A-39F840A38C3E}" ascii //weight: 1
        $x_1_6 = "OX4\\exlkiller.bat" ascii //weight: 1
        $x_1_7 = "rd /s /q %windir%\\Temp & md %windir%\\Temp" ascii //weight: 1
        $x_1_8 = "api=JUqYrgp|H370JWlhZKHiejE2lZA|MH171C|MH171C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ABM_2147924695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ABM!MTB"
        threat_id = "2147924695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 07 47 08 c0 74 dc 89 f9 79 07 0f b7 07 47 50 47 b9 57 48 f2 ae 55 ff 96 3c 64 2d 00 09 c0 74 07 89 03 83 c3 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ABM_2147924695_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ABM!MTB"
        threat_id = "2147924695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 68 00 01 00 84 8d 94 24 9c 00 00 00 52 ff 15 ?? ?? ?? ?? 8b 4c 24 18 50 8d 84 24 a0 00 00 00 50 51 55 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 00 50 56 51 6a 01 ff d3 8b 4c 24 18 8d 54 24 14 52 55 8d 04 37 50 51 ff 15}  //weight: 1, accuracy: High
        $x_3_3 = {83 c4 04 58 a3 ?? ?? ?? ?? b8 5b 25 47 00 50 8b 1d ?? ?? ?? ?? 85 db 74 09 53 e8 ?? ?? ?? ?? 83 c4 04 58}  //weight: 3, accuracy: Low
        $x_4_4 = "57B16C3F-8EB1-4487-B147-CC746A0B8877" ascii //weight: 4
        $x_5_5 = "B869706B42F0C202E5667F22DA1C9CF5" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GB_2147925375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GB!MTB"
        threat_id = "2147925375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 17 88 10 8a 57 01 88 50 01 8a 57 02 41 88 50 02 83 c0 03 8b de 0f b6 79 ff 83 e7 03 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_NIT_2147927780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.NIT!MTB"
        threat_id = "2147927780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a1 04 d0 41 00 56 85 c0 be 04 d0 41 00 74 17 8b 0d 00 d0 41 00 6a 00 51 6a 01 ff d0 8b 46 04 83 c6 04 85 c0}  //weight: 2, accuracy: High
        $x_1_2 = "Delete00.bat" ascii //weight: 1
        $x_1_3 = "blackmoon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GTC_2147931045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GTC!MTB"
        threat_id = "2147931045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {84 03 00 0c 85 ?? ?? ?? ?? 03 00 34 85 03 00 30 89 03 00 b6 83}  //weight: 5, accuracy: Low
        $x_5_2 = {3e 8a 03 00 50 ?? 03 00 58 8a 03 00 66 ?? 03 00}  //weight: 5, accuracy: Low
        $x_1_3 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_ABMN_2147931211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.ABMN!MTB"
        threat_id = "2147931211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 00 00 00 68 00 10 00 00 68 64 00 00 00 68 00 00 00 00 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? 39 65 ec 74 0d 68 06 00 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 f8 89 65 ec 68 40 00 00 00 68 00 10 00 00 68 64 00 00 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GTS_2147932046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GTS!MTB"
        threat_id = "2147932046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 46 33 20 20 cd b7 d0 d8 c7 d0 bb ?? ?? ?? ?? 46 34 20 20 cf d4 ca be ?? ?? ?? ?? 20 20 00 20 20 20 41 49}  //weight: 10, accuracy: Low
        $x_1_2 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GNS_2147932356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GNS!MTB"
        threat_id = "2147932356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b4 8d b6 29 33 06 32 d6 89 d1}  //weight: 5, accuracy: High
        $x_5_2 = {95 32 04 20 83 c3 43 5d 80 30 39 b8 ?? ?? ?? ?? d5 f7 8c a2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GKT_2147933349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GKT!MTB"
        threat_id = "2147933349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 4c d0 30 1f 64 fd 3f d5 15 34 8e fb 64 45}  //weight: 10, accuracy: High
        $x_1_2 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackMoon_GTK_2147934695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMoon.GTK!MTB"
        threat_id = "2147934695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 04 03 02 03 07 10 09 18 0a 02 06}  //weight: 5, accuracy: High
        $x_5_2 = {02 03 0a 9f ?? ?? ?? ?? 04 07 03 2b 0a 03 82 36}  //weight: 5, accuracy: Low
        $x_1_3 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

