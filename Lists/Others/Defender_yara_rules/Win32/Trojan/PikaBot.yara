rule Trojan_Win32_PikaBot_LK_2147847101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.LK!MTB"
        threat_id = "2147847101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 1c 01 8b 86 ?? ?? ?? 00 ff 86 ?? ?? ?? 00 48 31 05 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_SA_2147847565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.SA!MTB"
        threat_id = "2147847565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 15 ?? 33 c8 3a d2 74 ?? 8b 45 ?? 8b 40 ?? eb ?? 8b 45 ?? 0f b6 4c 05 ?? 66 3b c0 74 ?? 89 45 ?? 8b 45 ?? e9 ?? ?? ?? ?? 8b 45 ?? 8b 00 e9 ?? ?? ?? ?? c9 c3 8b 45 ?? 40 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_LKA_2147847665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.LKA!MTB"
        threat_id = "2147847665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 33 30 06 46 83 ef 01 75 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_LKC_2147847820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.LKC!MTB"
        threat_id = "2147847820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0d b0 34 ?? 88 84 0d ?? ?? ff ff 41 83 f9 0c 7c ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_SB_2147850299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.SB!MTB"
        threat_id = "2147850299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 0d 6c ff ff ff 32 c2 88 44 0d ?? 41 83 f9 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 08 8d 43 ?? 0f b6 c8 8d 53 ?? 80 fa ?? 0f b6 c3 0f 47 c8 8b 45 ?? 6b f6 ?? 0f be c9 03 f1 8b 4d ?? 40 89 45 ?? 3b c7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCCB_2147892311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCCB!MTB"
        threat_id = "2147892311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 48 50 8b 88 ?? ?? ?? ?? 2b 48 10 01 0d ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 50 40 33 90 ?? ?? ?? ?? 2b ca 01 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 01 8a ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCCE_2147892420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCCE!MTB"
        threat_id = "2147892420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 07 83 c7 ?? 0f af 59 ?? 8b 46 ?? 35 ?? ?? ?? ?? 0f af 81 ?? ?? ?? ?? 89 81 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 33 86 ?? ?? ?? ?? 2d ?? ?? ?? ?? 01 46 ?? 8b 86 ?? ?? ?? ?? 33 46 ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_DS_2147893951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.DS!MTB"
        threat_id = "2147893951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e f7 f6 eb ?? 83 c3 ?? 53 3a ff 74 ?? 33 c8 8b 45 ?? eb ?? 8b 00 89 45 ?? e9 ?? ?? ?? ?? 8b 45 ?? 48 e9 ?? ?? ?? ?? 89 45 ?? e9 ?? ?? ?? ?? 8b 45 ?? eb ?? 03 41 ?? 39 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_ES_2147893952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.ES!MTB"
        threat_id = "2147893952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 db 8d 4d ?? 45 be ?? ?? ?? ?? 32 ed 34 ?? 4b d7 32 3e 32 ad ?? ?? ?? ?? a5}  //weight: 1, accuracy: Low
        $x_1_2 = "Crash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCDB_2147894308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCDB!MTB"
        threat_id = "2147894308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 33 d2 eb ?? 0f b6 44 10 10 33 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_KS_2147894440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.KS!MTB"
        threat_id = "2147894440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 f6 f1 af 31 92 ?? ?? ?? ?? ?? b0 ?? 79 ?? 25 ?? ?? ?? ?? c4 b7 ?? ?? ?? ?? 46 e3 ?? ?? ?? ?? ?? e8 a8 ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {9e 02 cf b5 ?? b3 ?? a9 ?? ?? ?? ?? ?? e8 b4 ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = "Crash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCDG_2147894659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCDG!MTB"
        threat_id = "2147894659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 e9}  //weight: 1, accuracy: High
        $x_1_2 = {03 45 f0 0f b6 08}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f0 33 d2}  //weight: 1, accuracy: High
        $x_1_4 = {f7 f6 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_5 = {0f b6 44 10 10 33 c8}  //weight: 1, accuracy: High
        $x_1_6 = {8b 45 e8 03 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCDM_2147895042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCDM!MTB"
        threat_id = "2147895042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc 32 c3 fc}  //weight: 1, accuracy: High
        $x_1_2 = {02 c3 32 c3 c0 c8 c0 fc e9}  //weight: 1, accuracy: High
        $x_1_3 = {8a db aa fc 49 fc}  //weight: 1, accuracy: High
        $x_1_4 = "Excpt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_ZZ_2147895053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.ZZ"
        threat_id = "2147895053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {33 d2 8a 9c ?? ?? ?? ?? ?? 6a ?? 8b c6 59 f7 f1 0f b6 cb 0f b6 84 ?? ?? ?? ?? ?? 03 c7 03 c8 0f b6 f9 8a 84 ?? ?? ?? ?? ?? 88 84 ?? ?? ?? ?? ?? 46 88 9c ?? ?? ?? ?? ?? 81 fe 00 01 00 00 72}  //weight: 100, accuracy: Low
        $x_100_3 = {8d 47 01 0f b6 f8 8a 8c ?? ?? ?? ?? ?? 0f b6 d1 8d 04 1a 0f b6 d8 8a 84 ?? ?? ?? ?? ?? 88 84 ?? ?? ?? ?? ?? 88 8c ?? ?? ?? ?? ?? 0f b6 84 ?? ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 ?? ?? ?? ?? ?? 32 44 ?? ?? 88 84 ?? ?? ?? ?? ?? 46 83 fe}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_AA_2147895241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.AA!MTB"
        threat_id = "2147895241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "curl" wide //weight: 10
        $x_10_3 = "http://" wide //weight: 10
        $x_10_4 = "rundll32" wide //weight: 10
        $x_1_5 = "CrashForExceptionExportThunk" wide //weight: 1
        $x_1_6 = "CrashForException_ExportThunk" wide //weight: 1
        $x_1_7 = "Crash" wide //weight: 1
        $x_1_8 = "scab" wide //weight: 1
        $x_1_9 = "Excpt" wide //weight: 1
        $x_10_10 = "exit" wide //weight: 10
        $n_100_11 = "msedgewebview2.exe" wide //weight: -100
        $n_1000_12 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PikaBot_SM_2147895418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.SM!MTB"
        threat_id = "2147895418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 8b 45 ?? eb ?? bb ?? ?? ?? ?? 83 c3 ?? eb ?? bb ?? ?? ?? ?? 21 5d ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 10 ?? 33 c8 eb ?? 21 5d ?? e9 ?? ?? ?? ?? 8b 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_YX_2147895527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.YX!MTB"
        threat_id = "2147895527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 07 83 c7 04 a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 33 46 ?? 35 ?? ?? ?? ?? 89 46 ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 c1 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 5e ?? 0f af da 8b 88 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 8b d3 c1 ea ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCDX_2147896371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCDX!MTB"
        threat_id = "2147896371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 8b 45 e4 33 d2}  //weight: 1, accuracy: High
        $x_1_2 = {bb 05 00 00 00 83 c3 03 53}  //weight: 1, accuracy: High
        $x_1_3 = {5e f7 f6 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 44 10 10 33 c8 8b 45 dc}  //weight: 1, accuracy: High
        $x_1_5 = {03 45 e4 88 08}  //weight: 1, accuracy: High
        $x_1_6 = {40 89 45 e4 8b 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCET_2147897762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCET!MTB"
        threat_id = "2147897762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f0 0f b6 82 ?? ?? ?? ?? 8b 4d f0 81 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c2 8b 4d fc 03 4d f0 88 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f0 83 c0 01 89 45 f0 8b 4d f0 3b 4d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCFB_2147898613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCFB!MTB"
        threat_id = "2147898613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 10 8b 45 ?? 03 45 ?? 2d ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCFD_2147898656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCFD!MTB"
        threat_id = "2147898656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 8b 85 ?? ?? ?? ?? 0f b6 0c 08 8b 85 ?? ?? ?? ?? 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca 8b 85 ?? ?? ?? ?? 2b 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCFJ_2147899129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCFJ!MTB"
        threat_id = "2147899129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 01 8b 85 ?? fe ff ff 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca 8b 85 ?? fe ff ff 2b 85 ?? ff ff ff 03 85 ?? ff ff ff 8b 95 ?? ff ff ff 88 0c 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCFK_2147899500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCFK!MTB"
        threat_id = "2147899500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 0f af 45 ?? 2b d0 03 55 ?? 03 55 ?? 2b 55 ?? 0f b6 54 15 ?? 33 ca 8b 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PikaBot_CCIA_2147906593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBot.CCIA!MTB"
        threat_id = "2147906593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 45 e4 0f b6 08 eb}  //weight: 1, accuracy: High
        $x_1_2 = {f7 f6 8b 45 f8 eb}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 44 10 10 33 c8 eb}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 dc 03 45 e4 e9}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 e4 40 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

