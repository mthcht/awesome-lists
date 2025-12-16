rule Trojan_Win32_Androm_E_2147730708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.E!MTB"
        threat_id = "2147730708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 e8 6a cc f9 ff 4b 75 f6 bb [0-6] 6a 00 e8 5b cc f9 ff 4b 75 f6 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 90 90 8b 45 08 8a 10 80 f2 7b 88 10 5d c2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 03 c3 73 05 e8 [0-6] 50 ff 15 [0-6] 90 ff 06 81 3e [0-6] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Androm_DA_2147740350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.DA!MTB"
        threat_id = "2147740350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 41 41 41 41 [0-4] 59 [0-4] 46 [0-4] 8b 17 [0-4] 31 f2 66 ?? ?? ?? ?? 39 ca 75 ?? [0-32] b9 ?? ?? ?? ?? [0-6] 83 e9 04 [0-4] 8b 14 0f [0-4] 56 [0-4] 33 14 24 [0-4] 5e [0-4] 89 14 08 [0-4] 83 f9 00 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_V_2147743792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.V!MTB"
        threat_id = "2147743792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e4 8b 4d ?? 83 e1 ?? 0f be 04 08 8b 4d ?? 0f b6 54 0d ?? 31 c2 88 d3 88 5c 0d ?? 8b 45 ?? 83 c0 ?? 89 45 ?? e9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 e4 8b 4d ?? 83 e1 ?? 0f be 04 08 8b 4d ?? 0f b6 14 0d ?? ?? ?? ?? 31 c2 88 d3 88 1c 0d ?? ?? ?? ?? 8b 45 ?? 83 c0 ?? 89 45 ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Androm_VB_2147751316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.VB!MTB"
        threat_id = "2147751316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "Svflz5VonYuaXOqenZShmTWXNltVymNa175" wide //weight: 1
        $x_1_3 = "cZHMFuHv86" wide //weight: 1
        $x_1_4 = "mW9C6rNuksNAVfU1CrRQlXp8SlttBi226" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_DSK_2147754589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.DSK!MTB"
        threat_id = "2147754589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 30 8b 8c 24 ?? ?? ?? ?? 89 38 5f 5e 89 68 04 5d 5b 33 cc e8 ?? ?? ?? ?? 81 c4 2c 08 00 00 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BA_2147756613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BA!MTB"
        threat_id = "2147756613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 00 00 00 00 80 34 01 ?? 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc 05 db 7e 00 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 b9 00 00 00 00 91 f7 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_KE_2147759446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.KE"
        threat_id = "2147759446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConsoleApp53.exe" ascii //weight: 1
        $x_1_2 = "\\source\\repos\\dropper\\ConsoleApp53\\obj\\Debug\\ConsoleApp53.pdb" ascii //weight: 1
        $x_1_3 = "$5a2177b8-a9d5-46b3-92ea-94bdedff72d5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_VD_2147761765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.VD!MTB"
        threat_id = "2147761765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b de 03 d9 [0-64] 8b c1 bf ?? ?? ?? ?? 33 d2 f7 f7 85 d2 [0-64] 80 33 [0-64] 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_A_2147763712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.A!MTB"
        threat_id = "2147763712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 68 a1 a4 ad 1f 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 30 00 00 68 b4 d3 de 1d 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {51 54 6a 40 68 77 5b 00 00 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = "vJSuY2tvmzEo1U2" ascii //weight: 1
        $x_1_5 = "Dh2SJmBRPQlDZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RR_2147763894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RR!MTB"
        threat_id = "2147763894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f8 6a 04 68 ?? ?? 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 89 45 ?? b1 ?? ba 01 8b 45 03 e8 ?? ?? ?? ?? 8d 45 f8 50 68 ?? ?? ?? ?? 68 01 8b 45 03 50 e8 ?? ?? ?? ?? be e8 1d 04 00 8b 7d 03 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff b8 00 00 00 00 f7 f0 89 f6 89 f6 89 f6 [0-47] 8b c6 5e 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_AF_2147767244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.AF!MTB"
        threat_id = "2147767244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 52 50 8b c3 [0-4] 03 [0-4] 13 54 [0-4] 71 ?? e8 [0-4] 83 c4 ?? 8a 00 50 8b c7 33 d2 52 50 8b c3 [0-4] 03 ?? ?? 13 54 ?? ?? 71 ?? e8 [0-4] 83 c4 ?? 5a 88 10 [0-4] f3 0f 10 e4 [0-4] 43 4e 75}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 0f 10 ed 33 db a1 [0-6] 03 c3 73 ?? e8 [0-6] 8a 00 [0-6] f3 0f 10 c9 f3 0f 10 e4 34 ?? 8b 15 [0-6] 03 d3 73 ?? e8 [0-6] 88 02 f3 0f 10 db f3 0f 10 ed f3 0f 10 ff 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_R_2147779070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.R!MTB"
        threat_id = "2147779070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 84 0a 56 c4 08 00 8b 15 [0-4] 88 04 0a 81 c4 74 02 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {33 ce 33 c1 2b f8}  //weight: 1, accuracy: High
        $x_1_3 = {33 d7 33 c2 2b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Androm_RW_2147786814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RW!MTB"
        threat_id = "2147786814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 89 95 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 05 7d ?? 8b 85 ?? ?? ?? ?? 99 b9 03 00 00 00 f7 f9 8b 45 ?? 0f be 0c 10 8b 95 ?? ?? ?? ?? 0f b6 44 15 ?? 33 c1 8b 8d ?? ?? ?? ?? 88 44 0d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RT_2147788937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RT!MTB"
        threat_id = "2147788937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iO%WL1nN*XL7kF1sB1qR1WEHeFCmJ9pJC" ascii //weight: 1
        $x_1_2 = "http://www.ssnbc.com/wiz/" ascii //weight: 1
        $x_1_3 = "Alasses\\WOW6432Node\\CLS" ascii //weight: 1
        $x_1_4 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_SIBA_2147794852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.SIBA!MTB"
        threat_id = "2147794852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 e4 8d 83 [0-208] 81 e0 00 00 00 00 0b 04 e4 83 c4 04 89 4d ?? 29 c9 09 c1 89 cf 8b 4d 01 30 01 89 55 ?? 83 e2 00 0b 93 49 22 47 00 83 e6 00 09 d6 8b 55 04 [0-208] 31 ed 33 ab ?? ?? ?? ?? 89 e9 5d 55 83 24 e4 00 01 0c e4 [0-80] 83 ec fc [0-112] 31 c9 8f 45 ?? 0b 4d 0a fc 57 83 24 e4 00 09 0c e4 [0-112] 83 c4 04 [0-112] 8f 45 ?? 8b 4d 0e f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = {57 c7 04 e4 ff ff 0f 00 59 56 31 34 e4 09 0c e4 [0-208] 83 ec fc [0-208] 81 e1 00 00 00 00 8b 0c e4 83 c4 04 [0-208] 53 83 24 e4 00 01 0c e4 [0-208] 83 ec fc [0-208] 8f 45 ?? 8b 4d 05 8f 45 ?? 8b 45 07 50 c7 04 e4 ?? ?? ?? ?? 52 83 24 e4 00 09 04 e4 52 83 24 e4 00 01 0c e4 [0-208] 81 e1 00 00 00 00 8b 0c e4 83 c4 04 81 e0 00 00 00 00 8f 45 ?? 03 45 0b 8f 83 ?? ?? ?? ?? [0-208] c7 45 ?? 00 00 00 00 ff 75 0f 09 0c e4 [0-208] 81 e1 00 00 00 00 8b 0c e4 83 c4 04 8f 45 ?? 8b 45 12 21 8b 0d 56 83 24 e4 00 09 04 e4 [0-208] 8f 45 ?? 8b 45 16 89 7d ?? 89 c7 03 bb 0d 57 8b 7d 18 8f 83 0d [0-208] ff a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Androm_UTK_2147794923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.UTK!MTB"
        threat_id = "2147794923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apocatastasis" ascii //weight: 1
        $x_1_2 = "Maskinskrivning" ascii //weight: 1
        $x_1_3 = "Identitetsmrkernes" ascii //weight: 1
        $x_1_4 = "Strengthfulness6" ascii //weight: 1
        $x_1_5 = "Unconceptualized3" ascii //weight: 1
        $x_1_6 = "BEZPOPOVETS" ascii //weight: 1
        $x_1_7 = "HOVEDGADEN" ascii //weight: 1
        $x_1_8 = "SLUTAKTER" ascii //weight: 1
        $x_1_9 = "Backfische6" ascii //weight: 1
        $x_1_10 = "fremmedbgers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_AES_2147795453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.AES!MTB"
        threat_id = "2147795453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 fa 05 0f b6 45 ff c1 e0 03 0b d0 88 55 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 84 00 00 00 88 55 ff 0f b6 45 ff 83 c0 4a 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 83 c2 6f 88 55 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_FC_2147805865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.FC!MTB"
        threat_id = "2147805865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stenoglossa" wide //weight: 1
        $x_1_2 = "slusekamrenes" wide //weight: 1
        $x_1_3 = "Beskyttelsesforanstaltningernes" wide //weight: 1
        $x_1_4 = "Portefljemanagers" wide //weight: 1
        $x_1_5 = "Bogbinderiers" wide //weight: 1
        $x_1_6 = "RQoB4lIv87LwObv192" wide //weight: 1
        $x_1_7 = "Menneskekrligstes8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RPI_2147831535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RPI!MTB"
        threat_id = "2147831535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 6c 8b 74 24 2c 8b 7c 24 20 03 c6 89 44 24 14 8a 00 88 44 24 27 8b c7}  //weight: 1, accuracy: High
        $x_1_2 = {0f af ca 0f af ce 0f af cf 0f af 4c 24 50 8b f9 89 7c 24 20 8a 8c 24 80 00 00 00 32 4c 24 27 3b c3 88 4c 24 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RC_2147831659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RC!MTB"
        threat_id = "2147831659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 54 24 08 52 6a 40 68 78 da 04 00 56 ff d0 6a 00 6a 00 56 56 6a 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RC_2147831659_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RC!MTB"
        threat_id = "2147831659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ce 0d 3c 61 0f be c0 7c 03 83 e8 20 03 f0 41 8a 01 84 c0 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8b c6 f7 f3 8a 0c 2a 30 0c 3e 46 3b 74 24 18 72 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RA_2147832809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RA!MTB"
        threat_id = "2147832809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b c8 00 0f be 54 0d f4 b8 01 00 00 00 c1 e0 00 0f be 4c 05 f4 c1 f9 04 8d 14 91 8b 45 ec 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_GBR_2147833893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.GBR!MTB"
        threat_id = "2147833893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 e0 8a 45 fe 4e fe c8 33 c9 3a 45 d0 88 45 fe 8b 45 ec 0f 94 c1 83 f1 0c 0f be c0 09 4d 9c 83 e8 0d 74 09 85 d2 74 05 33 c0}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4d ff 4e 33 c0 fe 4d fe 80 7d fe 04 0f 94 c0 83 f0 0c 09 45 c8 0f be c1 83 e8 0d 74 09 85 d2 74 05 33 c0 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RG_2147833960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RG!MTB"
        threat_id = "2147833960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ca 0d 3c 61 0f be c0 7c 03 83 e8 20 03 d0 41 8a 01 84 c0 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8b c6 f7 f3 8a 0c ?? 30 0c 3e 46 [0-6] 3b [0-6] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RH_2147835248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RH!MTB"
        threat_id = "2147835248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c9 0d 8b c1 c3 [0-32] 0f be ca 80 fa 61 7c 03 83 e9 20 03 c1 46 8a 16 84 d2 75 e3 [0-160] 33 d2 8b c6 f7 75 ?? 8a 0c 1a 30 0c 3e 46 3b 75 ?? 72 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_AN_2147838077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.AN!MTB"
        threat_id = "2147838077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 89 85 02 ff ff ff ba ?? ?? ?? ?? 66 89 95 00 ff ff ff b8 ?? ?? ?? ?? 6b c8 00 8b 55 88 8b 42 0c 8b 0c 01 8b 11 89 95 04 ff ff ff 6a ?? 8d 85 00 ff ff ff 50 8b 4d ec 51}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RB_2147838395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RB!MTB"
        threat_id = "2147838395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 04 8b c8 0f be c2 80 fa 61 7c 03 83 e8 20 8a 56 01 46 03 c8 84 d2 75 e0 8b c1 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {cc cc c1 c9 0d 8b c1 c3 cc cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RB_2147838395_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RB!MTB"
        threat_id = "2147838395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ff 00 00 00 7d 0b 8b 4d f0 33 4d f4 89 4d f0 eb e3 8b 55 f0 33 55 ec 83 f2 0f 8b 45 08 03 45 fc 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_CAB_2147840575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.CAB!MTB"
        threat_id = "2147840575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 1c 10 8a 1b 32 d9 8d 34 02 88 1e 42 81 ?? ?? ?? ?? ?? 75}  //weight: 5, accuracy: Low
        $x_1_2 = "SetBoundsRect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EC_2147841585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EC!MTB"
        threat_id = "2147841585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Retinae0.exe" wide //weight: 1
        $x_1_2 = "Flokite3" wide //weight: 1
        $x_1_3 = "Itumkala1" ascii //weight: 1
        $x_1_4 = "Zanzibaris4" ascii //weight: 1
        $x_1_5 = "CreateTimerQueueTimer" ascii //weight: 1
        $x_1_6 = "SleepEx" ascii //weight: 1
        $x_1_7 = "ReadEventLogA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EC_2147841585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EC!MTB"
        threat_id = "2147841585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ieOculto_DocumentComplete" ascii //weight: 1
        $x_1_2 = "checarbrowser" ascii //weight: 1
        $x_1_3 = "Escritorio\\modifica Agosto2" wide //weight: 1
        $x_1_4 = "ExecQuery" wide //weight: 1
        $x_1_5 = "-C000-Rec32" ascii //weight: 1
        $x_1_6 = "ieReturnSourceServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EH_2147846235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EH!MTB"
        threat_id = "2147846235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HojoJLdjnsA2clt" ascii //weight: 1
        $x_1_2 = "qTpvi3vfYFz" ascii //weight: 1
        $x_1_3 = "2rfkindysadvnqw3nerasdf" ascii //weight: 1
        $x_1_4 = "EIdEmailParse" ascii //weight: 1
        $x_1_5 = "GetAcceptExSockaddrs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RJ_2147849451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RJ!MTB"
        threat_id = "2147849451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c0 83 c8 60 03 c7 03 c0 42 8b f8 8a 02 84 c0 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RPX_2147850293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RPX!MTB"
        threat_id = "2147850293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 51 57 e8 ?? ?? ?? ?? 83 c4 0c 6a 40 68 00 30 00 00 56 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 60 2b 4c 24 5c 51 57 50 89 44 24 60 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "38.55.194.104" wide //weight: 1
        $x_1_3 = "output_32.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_MBHX_2147888496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.MBHX!MTB"
        threat_id = "2147888496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 33 00 65 00 34 00 64 00 33 00 64 00 34 00 32 00 34 00 31 00 33 00}  //weight: 1, accuracy: High
        $x_1_2 = {02 9e 40 00 58 1f 40 00 10 f2 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 04 00 00 00 e9 00 00 00 88 15 40 00 80 14 40 00 3c 14 40 00 78 00 00 00 8a}  //weight: 1, accuracy: High
        $x_1_3 = "kunjsfuzjnsdmmxzw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_NAM_2147892431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.NAM!MTB"
        threat_id = "2147892431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 3a 8b 8d ?? ?? ?? ?? 2b cb 03 4d 10 33 c0 40 3b c8 0f 86 a5 01 00 00 6a 02 8d 85 44 e5 ff ff 53 50 e8 48 aa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EM_2147894982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EM!MTB"
        threat_id = "2147894982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 98 30 80 40 00 32 d9 88 98 30 80 40 00 40 83 f8 08 7c ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EM_2147894982_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EM!MTB"
        threat_id = "2147894982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b fb c1 e9 02 f3 a5 8b ca 83 e1 03 85 c0 f3 a4 75 0b 5f 5e 5d 5b 81 c4 04 06 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EM_2147894982_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EM!MTB"
        threat_id = "2147894982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b f8 8b d1 81 c6 90 da 04 00 8b df c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 5f 5e 85 db 5b 75 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_NA_2147896735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.NA!MTB"
        threat_id = "2147896735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 6d 31 b4 3a 55 00 28 ea 45 00 5e 00 05 ?? ?? ?? ?? 31 00 00 8b c0 55 8b ec 81 c4 ?? ?? ?? ?? 53 89 45 94}  //weight: 5, accuracy: Low
        $x_1_2 = "inquire_v1XpT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_ES_2147900271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.ES!MTB"
        threat_id = "2147900271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d b4 24 18 05 00 00 6a 0a 8d 7c 2a 10 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 01 45 04 ff d3 6a 0a ff d3 6a 0a ff d3}  //weight: 10, accuracy: High
        $x_1_2 = "One night -- it was on the twentieth of March, 1888" ascii //weight: 1
        $x_1_3 = "hdietrich2@hotmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_AMAF_2147901265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.AMAF!MTB"
        threat_id = "2147901265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 31 45 fc 33 55 fc 89 55 d0 8b 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BKL_2147928081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BKL!MTB"
        threat_id = "2147928081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be a5 15 4f 0b 1c 09 30 65 89 7a f4 3c 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BKL_2147928081_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BKL!MTB"
        threat_id = "2147928081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 04 0f b6 10 32 55 e4 88 10 83 45 f4 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 e8 89 45 e4 8b 45 e4 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EAMG_2147928922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EAMG!MTB"
        threat_id = "2147928922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b7 14 41 0f be 45 97 03 d0 8b 8d f0 fe ff ff 03 4d a0 88 11}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_RAA_2147937530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.RAA!MTB"
        threat_id = "2147937530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 45 84 89 85 38 ff ff ff 8d 85 34 ff ff ff 50 8d 85 20 ff ff ff 50 8d 85 38 ff ff ff 50 8b 45 08 8b 00 ff 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {83 a5 60 ff ff ff 00 8b 45 a4 89 85 68 ff ff ff 83 65 a4 00 8b 95 68 ff ff ff 8d 4d a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_AD_2147944983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.AD!MTB"
        threat_id = "2147944983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4d ff bf b4 53 40 00 88 4d e0 83 c9 ff 33 c0 89 75 e4 f2 ae f7 d1 49 89 75 e8 51 68 b4 53 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAA_2147949078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAA!MTB"
        threat_id = "2147949078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 0e 8d 49 01 88 41 ff 42 8b 45 10 3b d0 72}  //weight: 2, accuracy: High
        $x_2_2 = {8b c1 c1 e8 10 30 04 1a 42 3b 55 10 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAB_2147949082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAB!MTB"
        threat_id = "2147949082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 08 8a 00 34 f7 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 71 ?? ?? ?? ?? ?? ?? 83 c4 08 5a 88 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EFVY_2147952599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EFVY!MTB"
        threat_id = "2147952599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc}  //weight: 2, accuracy: High
        $x_2_2 = {03 4d f8 8b 55 e0 03 55 f8 8a 02 88 01 83 7d f8 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EVPP_2147952600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EVPP!MTB"
        threat_id = "2147952600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 0e 8d 49 01 88 41 ff 42 8b 45 fc 3b d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EVVW_2147952605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EVVW!MTB"
        threat_id = "2147952605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c1 8b 55 f8 c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc}  //weight: 2, accuracy: High
        $x_2_2 = {03 4d f8 8b 55 e4 03 55 f8 8a 02 88 01 83 7d f8 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EFWY_2147952628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EFWY!MTB"
        threat_id = "2147952628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 45 0c 33 c8 8d 04 33 33 c8 2b f9 8b cf 8b c7}  //weight: 2, accuracy: High
        $x_2_2 = {8a 0c 1a 88 0c 02 42 8b 45 a0 3b d0 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_EFSD_2147952629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.EFSD!MTB"
        threat_id = "2147952629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b ce c1 e1 04 03 4d ec 33 c1 8d 0c 33 33 c1 2b f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAE_2147955938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAE!MTB"
        threat_id = "2147955938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 16 0f b6 44 10 ff 33 07 5a 88 02 ff 06 4b 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAE_2147955938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAE!MTB"
        threat_id = "2147955938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b f0 8b 45 c8 31 30 83 c3 04 83 45 c8 04 3b 5d c4 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAD_2147956284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAD!MTB"
        threat_id = "2147956284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8a 54 1d ff 33 d7 f7 d2 88 54 18 ff 43 4e 75 ?? 59 5a 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_KK_2147956385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.KK!MTB"
        threat_id = "2147956385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 19 99 59 f7 f9 80 c2 61 88 54 35 c0 46 83 fe 07}  //weight: 10, accuracy: High
        $x_5_2 = "hytr7fisgfhtro39" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_KK_2147956385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.KK!MTB"
        threat_id = "2147956385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AppData@-@jvr2.exe@-@jvr" ascii //weight: 10
        $x_1_2 = "RemoteHook1" ascii //weight: 1
        $x_1_3 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" ascii //weight: 1
        $x_1_4 = "/t REG_SZ /d" ascii //weight: 1
        $x_1_5 = "-notray" ascii //weight: 1
        $x_1_6 = "PeIn.exe" ascii //weight: 1
        $x_1_7 = "\\system32\\ipconfig.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAF_2147957594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAF!MTB"
        threat_id = "2147957594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 45 cc 2b c2 83 c0 04 89 45 ec ff 75 fc b9 21 00 00 00 ff 75 f8 b9 21 00 00 00 ff 75 f0 b9 21 00 00 00 ff 75 f4 b9 21}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAF_2147957594_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAF!MTB"
        threat_id = "2147957594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 fa 03 fb 03 f8 c7 45 ?? 16 19 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d ?? 81 ef 16 19 00 00 2b f8 6a 00 e8 [0-31] 03 f8 31 3e 83 c3 04 83 c6 04 3b 5d ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAG_2147958976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAG!MTB"
        threat_id = "2147958976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 fa 03 fb 03 f8 c7 45 ?? 39 19 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d a8 81 ef 39 19 00 00 2b f8 6a 00 e8 [0-31] 03 f8 31 3e 83 c3 04 83 c6 04 3b 5d cc 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Androm_BAI_2147959341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Androm.BAI!MTB"
        threat_id = "2147959341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 ff 01 1e b8 ?? ?? ?? ?? 03 45 ?? 03 c3 03 c7 89 45 ?? c7 45 ?? 39 19 00 00 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {5a 2b d0 31 16 83 c3 04 83 c6 04 3b 5d ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

