rule Trojan_Win32_Netwire_PA_2147742474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.PA!MTB"
        threat_id = "2147742474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 83 e0 03 8a 88 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c2 30 8a ?? ?? ?? ?? 83 e0 03 30 8a ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 03 c2 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 03 c2 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 8b 45 fc 8d 80 ?? ?? ?? ?? 03 c2 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 83 c2 06 81 fa ?? ?? 00 00 0f 82}  //weight: 2, accuracy: Low
        $x_1_2 = {51 6a 40 68 ?? ?? 00 00 68 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_PB_2147742631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.PB!MTB"
        threat_id = "2147742631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 38 03 8a 0c 38 8a 5c 38 01 8a 6c 38 02 88 55 ?? c0 65 ?? ?? 8a 45 ff 24 ?? 0a c8 8a c2 c0 e0 06 80 e2 ?? 88 45 ?? 0a e8 8b 45 ?? c0 e2 ?? 0a d3 88 0c 06 88 54 06 01 83 c6 02 88 2c 06 81 fe ?? ?? 00 00 77 ?? [0-16] 8b 45 ?? 03 7d ?? 46 3b 3d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_FW_2147742829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.FW!MTB"
        threat_id = "2147742829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 33 f6 85 ff 7e ?? 81 ff ?? ?? 00 00 75 ?? [0-4] ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c ?? 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_PC_2147743343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.PC!MTB"
        threat_id = "2147743343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 8d ?? ?? ff ff 81 bd ?? ?? ff ff ?? ?? 00 00 73 38 8b 85 ?? ?? ff ff 33 d2 b9 ?? 00 00 00 f7 f1 8b 85 ?? ?? ff ff 0f be 0c 10 8b 95 ?? ?? ff ff 0f b6 84 15 ?? ?? ff ff 33 c1 8b 8d ?? ?? ff ff 88 84 0d ?? ?? ff ff eb 06 00 8b 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff ?? 73 38 8b 85 ?? ?? ff ff 33 d2 b9 ?? 00 00 00 f7 f1 8b 85 ?? ?? ff ff 0f be 0c 10 8b 95 ?? ?? ff ff 0f b6 84 15 ?? ?? ff ff 33 c1 8b 8d ?? ?? ff ff 88 84 0d ?? ?? ff ff eb 06 00 8b 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Netwire_PR_2147745090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.PR!MTB"
        threat_id = "2147745090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 83 e0 03 0f b6 54 05 fc 30 94 35 18 fd ff ff 8d 7c 05 fc 8b c1 83 e0 03 8d 54 05 fc 0f b6 02 30 84 35 19 fd ff ff 8d 41 fe 8d 58 ff 83 e3 03 8a 5c 1d fc 30 9c 35 1a fd ff ff 83 e0 03 0f b6 44 05 fc 30 84 35 1b fd ff ff 0f b6 07 30 84 35 1c fd ff ff 0f b6 12 30 94 35 1d fd ff ff 83 c1 06 83 c6 06 81 f9 e3 02 00 00 72 93}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4d fe 8a 5d ff 8a d0 8a c4 34 2c 80 f2 df 80 f1 33 80 f3 35 3c 14 75 0e 80 f9 01 75 09 80 fa e9 75 04 84 db 74 09 8b 45 fc 40 89 45 fc eb d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_AA_2147745598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.AA!MTB"
        threat_id = "2147745598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca 88 55 ff 80 75 ff dc 8b da c1 e9 08 8b c2 c1 eb 10 80 f1 24 c1 e8 18 80 f3 35 34 37 80 f9 14 75 0f 80 fb 01 75 0a 84 c0 75 06 80 7d ff e9 74 03 42 eb cb}  //weight: 1, accuracy: High
        $x_1_2 = {8b c2 8d 8d 08 fd ff ff 83 e0 03 03 ca 83 c2 06 0f b6 44 05 f8 30 01 8d 04 0e 83 e0 03 0f b6 44 05 f8 30 41 01 8d 04 0f 83 e0 03 0f b6 44 05 f8 30 41 02 8d 04 0b 83 e0 03 0f b6 44 05 f8 30 41 03 8b 45 f4 03 c1 83 e0 03 0f b6 44 05 f8 30 41 04 8b 45 f0 03 c1 83 e0 03 0f b6 44 05 f8 30 41 05 81 fa e2 02 00 00 72 97}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_AA_2147745598_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.AA!MTB"
        threat_id = "2147745598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "filenames.txt" ascii //weight: 1
        $x_10_2 = "SOFTWARE\\NetWire" ascii //weight: 10
        $x_1_3 = "hostname" ascii //weight: 1
        $x_1_4 = "encryptedUsername" ascii //weight: 1
        $x_1_5 = "encryptedPassword" ascii //weight: 1
        $x_5_6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii //weight: 5
        $x_5_7 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" ascii //weight: 5
        $x_5_8 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 5
        $x_5_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 5
        $x_1_10 = "encrypted_key" ascii //weight: 1
        $x_5_11 = "%s\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_5_12 = "%s\\Chromium\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_5_13 = "%s\\Comodo\\Dragon\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_5_14 = "%s\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_5_15 = "%s\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_5_16 = "%s\\360Chrome\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_1_17 = "Host.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_AB_2147746022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.AB!MTB"
        threat_id = "2147746022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8a d1 80 f2 04 88 14 01 41 81 f9 ?? ?? ?? ?? 72 ef 4f 00 be ?? ?? ?? ?? 8d bd ?? ?? ff ff f3 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 0f 1f 44 00 00 8a ca 80 f1 04 88 0c 02 42 81 fa ?? ?? ?? ?? 72 ef 2f 00 6a ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 33 d2 0f 1f 44 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff ff d0 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? cc}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 40 68 41 06 00 00 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 68 00 fe 01 00 6a 07 6a 06 6a 09 68 20 41 40 00 8d 85 bc f9 ff ff ff d0 ff 15 00 00 40 00 6a 01 b9 01 00 00 00 c7 85 b8 f9 ff ff 01 00 00 00 e8 b3 df ff ff 6a 00 6a 00 ff 15 00 00 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 84 3d f8 fe ff ff 0f b6 c9 03 c8 0f b6 c1 8b 4d fc 8a 84 05 f8 fe ff ff 30 84 0d 14 fb ff ff 50 53 83 f3 23 81 c3 81 00 00 00 2b db b8 78 00 00 00 8b d8 83 e8 30 83 c3 1f 8b db b8 4a 00 00 00 83 c0 4b 35 da 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {0f b6 84 15 b4 f8 ff ff 0f b6 c9 03 c8 0f b6 c1 0f b6 84 05 b4 f8 ff ff 30 84 3d bc f9 ff ff 50 53 83 e8 50 33 d8 03 d8 83 e8 52 83 f3 17 33 d8 8b db 8b d8 83 e8 27 35 b6 00 00 00 33 db 2d b9 00 00 00 83 c0 56 33 db 83 c0 7a 81 c3 fb 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Netwire_GS_2147746100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.GS!MTB"
        threat_id = "2147746100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 55 f4 53 8b 5d f8 8b f8 53 57 e8 ?? ?? ff ff 8b 4d 08 33 d2 8b c6 f7 75 0c 8a 04 0a ba ?? ?? 00 00 30 04 37 46 3b f2 72 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_RG_2147753017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.RG!MTB"
        threat_id = "2147753017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cXWBthHlrUrvZx69mDkcu167" wide //weight: 1
        $x_1_2 = "IKhbBXeNH8D6pkkt60" wide //weight: 1
        $x_1_3 = "juSVh5JwaC55" wide //weight: 1
        $x_1_4 = "qrakHclLREuVH93" wide //weight: 1
        $x_1_5 = "BARzdBs2fsgCKwzxO8B7gms8HWhgMty3136" wide //weight: 1
        $x_1_6 = "KOuj1n1o1NLptei114" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Netwire_SU_2147753505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.SU!MTB"
        threat_id = "2147753505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Transplantationsdonorensbutsudanvedligeholdenesjovilabenurle" wide //weight: 1
        $x_1_2 = "HAPTENESVIEWPRODUKTHANDLENCLARSET" wide //weight: 1
        $x_1_3 = "Formidleresbiproduktercrowbellensilatemenneskeal5" wide //weight: 1
        $x_1_4 = "Ugennemskuelighederdomsmagtensmanendeministerpos4" wide //weight: 1
        $x_1_5 = "GUnnerBing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_ZV_2147753838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.ZV!MTB"
        threat_id = "2147753838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 83 f6 00 83 f6 00 ad 83 f6 00 66 3d 6e 36 85 c0 66 3d 4c 41 85 c0 85 c0 66 83 f8 28 8b 1c 0f 66 3d d1 2f 85 c0 83 f6 00 83 f6 00 66 3d a6 bb 83 f6 00 66 3d 8d a0 85 c0 83 f6 00 85 c0 31 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_V_2147753922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.V!MTB"
        threat_id = "2147753922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5d fb 8a d0 8a 45 [0-21] 8a cc 34 ?? 80 f2 ?? 80 f1 ?? 80 f3 ?? 3c [0-21] 8b 45 f8 40 89 45 f8 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 83 e1 [0-21] 8a 54 0d [0-21] 30 90 [0-21] 30 90 [0-21] 8b ce 83 e1 [0-21] 8a 4c 0d [0-21] 30 88 [0-21] 88 4d [0-21] 0f b6 55 [0-21] 30 90 [0-21] 8d 4e [0-21] 8d 79 [0-21] 83 e1 [0-21] 0f b6 4c 0d [0-21] 30 88 [0-21] 83 e7 [0-21] 8a 5c 3d [0-21] 30 98 [0-21] 83 c6 [0-21] 83 c0 [0-21] 81 fe [0-21] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_VB_2147754010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.VB!MTB"
        threat_id = "2147754010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "KthQhZzGWTyXIXppyaOnqrxMEF85" wide //weight: 1
        $x_1_3 = "I6QxGFUjE8FMgBFTVTdecpWtpaz2Cc145" wide //weight: 1
        $x_1_4 = "GWCCaOggRcV0KrJfcL0T6M3Oo0gEHUr119" wide //weight: 1
        $x_1_5 = "s21OkB3Mu8DHUwEhyMH2SeiIL64" wide //weight: 1
        $x_1_6 = "cvJlEroaUJBAM0gsXk0l7HAEj0g7EXEu144" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_B_2147799385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.B!MTB"
        threat_id = "2147799385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 8b 45 fc 2b 42 0c 6b c8 0c 51 8b 55 08 6b 42 0c 0c 8b 4d 08 03 01 50 8b 55 08 8b 42 0c 83 c0 40 6b c8 0c 8b 55 08 03 0a 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_P_2147831071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.P!MTB"
        threat_id = "2147831071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 32 c0 5e 8b 8c 24 ?? ?? ?? ?? 33 cc e8 ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? c3 8b ce 8d 51 01}  //weight: 1, accuracy: Low
        $x_1_2 = {90 8a 01 41 84 c0 75 f9 2b ca 8d 79 0a 81 ff 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_RPG_2147838785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.RPG!MTB"
        threat_id = "2147838785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $URL , $PATH )" wide //weight: 1
        $x_1_2 = "LOCAL $E = EXECUTE" wide //weight: 1
        $x_1_3 = "( $TITLE , $BODY , $TYPE )" wide //weight: 1
        $x_1_4 = "( $VDATA , $VCRYPTKEY )" wide //weight: 1
        $x_1_5 = "LOCAL $TBUFF" wide //weight: 1
        $x_1_6 = "LOCAL $TTEMPSTRUCT" wide //weight: 1
        $x_1_7 = "LOCAL $IPLAINTEXTSIZE" wide //weight: 1
        $x_1_8 = "LOCAL $VRETURN" wide //weight: 1
        $x_1_9 = "$__G_ACRYPTINTERNALDATA [" wide //weight: 1
        $x_1_10 = "$ARET = $E (" wide //weight: 1
        $x_1_11 = "$HCRYPTHASH = $ARET [" wide //weight: 1
        $x_1_12 = "$VCRYPTKEY = $VRETURN" wide //weight: 1
        $x_1_13 = "$BIN_SHELLCODE" wide //weight: 1
        $x_1_14 = "EXECUTE ( \"RunPE(@ScriptFullPath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_RPV_2147840897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.RPV!MTB"
        threat_id = "2147840897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOCAL $NSK =" wide //weight: 1
        $x_1_2 = "BITOR ( BITAND ( 90994 , 5288 ) , 5070 ) " wide //weight: 1
        $x_1_3 = "BITROTATE ( BITAND ( BITAND ( 17511 , 8035 ) , 9602 ) )" wide //weight: 1
        $x_1_4 = "SQRT ( SQRT ( INT ( 58185 ) ) )" wide //weight: 1
        $x_1_5 = "BITXOR ( BITNOT ( 17593 ) , 7479 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_NEAD_2147843343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.NEAD!MTB"
        threat_id = "2147843343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 d0 07 00 00 ff d3 83 ee 01 75 f4 68 c4 09 00 00 ff d3 6a 40 68 00 10 00 00 68 a0 33 03 00 56 ff 95 f8 fe ff ff}  //weight: 10, accuracy: High
        $x_2_2 = "Cyberdyne" ascii //weight: 2
        $x_2_3 = "XOR_Unsigned_Char_Array_CPP" ascii //weight: 2
        $x_2_4 = "ConsoleApplication1.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_NEAE_2147843345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.NEAE!MTB"
        threat_id = "2147843345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7d 34 40 0f b6 c0 8a 4c 04 10 01 ce 89 f2 0f b6 f2 0f b6 6c 34 10 89 ea 88 54 04 10 8b 54 24 0c 88 4c 34 10 01 e9 0f b6 c9 8a 4c 0c 10 30 0c 17 ff 44 24 0c eb c6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_RPY_2147849964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.RPY!MTB"
        threat_id = "2147849964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c0 31 c2 8b 45 ec 83 c0 0c 8b 00 31 d0 89 45 f0 8b 45 fc c1 e8 18 89 c2 8b 45 10 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_RPZ_2147849965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.RPZ!MTB"
        threat_id = "2147849965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 e4 8d 4d e4 80 75 e5 42 83 c4 04 80 75 e6 42 34 42 80 75 e7 42 88 45 e4 8b 45 dc 6a 00 6a 04 51 8b 40 04 8d 4d dc ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netwire_MBHH_2147851613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netwire.MBHH!MTB"
        threat_id = "2147851613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 e8 03 00 00 07 ac 0a 00 00 08 b4 04 00 00 ff 03 32 00 00 00 0c 08}  //weight: 1, accuracy: High
        $x_1_2 = {7c 18 40 00 fe f9 f7 01 20 ff ff ff 08}  //weight: 1, accuracy: High
        $x_1_3 = {e9 00 00 00 d4 29 40 00 c0 16 40 00 e8 13 40 00 78 00 00 00 82 00 00 00 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

