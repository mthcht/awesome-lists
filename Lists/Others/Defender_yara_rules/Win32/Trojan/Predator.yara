rule Trojan_Win32_Predator_J_2147731128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.J!MTB"
        threat_id = "2147731128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 d1 32 8c 14 ?? ?? ?? ?? 88 8c 14 ?? ?? ?? ?? 42 3b d7 73 09 8a 8c 24 ?? ?? ?? ?? eb e2}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8a 01 f6 d0 32 45 08 5d c2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_R_2147740927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.R!MTB"
        threat_id = "2147740927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 ff d7 ff d3 81 fe [0-4] 7e 12 81 7d [0-5] 74 09 81 7d [0-5] 75 0b 46 81 fe [0-4] 7c d1}  //weight: 1, accuracy: Low
        $x_2_2 = {88 14 01 40 3b 05 ?? ?? ?? ?? 72 e1 13 00 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_R_2147740927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.R!MTB"
        threat_id = "2147740927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 3b f0 72 66 00 3d 80 04 00 00 75 ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_2_2 = {8a c1 24 fc c0 e0 04 0a 44 33 01 8a d9 80 e1 f0 02 c9 02 c9 0a 0c 2e c0 e3 06 0a 5c 2e 02 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 04 42 3b 35 ?? ?? ?? ?? 72 bb 10 00 8b 1d ?? ?? ?? ?? 8a 4c 33 03 8b 2d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_R_2147740927_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.R!MTB"
        threat_id = "2147740927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0d 8b 85 ?? ?? ?? ?? 40 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 21 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 88 08 eb c4}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 07 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 7d 2a 8b 45 ?? 03 45 ?? 0f be 00 89 45 ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 eb c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_R_2147740927_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.R!MTB"
        threat_id = "2147740927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 55 e8 03 55 f0 89 55 e8 8b 45 0c 8b 4d e8 3b 08 0f 83 fc 00 00 00 8b 55 08 8b 02 8b 4d e8 8a 14 08 88 55 ed 8b 45 08 8b 08 8b 55 e8 8a 44 0a 01 88 45 f7 8b 4d 08 8b 11 8b 45 e8}  //weight: 1, accuracy: High
        $x_1_2 = {03 45 fc 8a 4d ed 88 08 8b 55 fc 83 c2 01 89 55 fc 8b 45 f8 03 45 fc 8a 4d f7 88 08 8b 55 fc 83 c2 01 89 55 fc 8b 45 f8 03 45 fc 8a 4d ef 88 08 8d 55 fc 52 e8 29 fe ff ff 83 c4 04 e9 ed fe ff ff}  //weight: 1, accuracy: High
        $x_5_3 = {0b c1 88 45 ?? 1b 00 c1 e1 ?? ?? ?? ?? ?? ?? ?? ?? 81 e2}  //weight: 5, accuracy: Low
        $x_5_4 = {0b d0 88 55 ?? 1b 00 c1 e0 ?? ?? ?? ?? ?? ?? ?? ?? 81 e1}  //weight: 5, accuracy: Low
        $x_5_5 = {0b ca 88 4d ?? 1a 00 c1 e2 ?? ?? ?? ?? ?? ?? ?? ?? 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_DSK_2147741175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.DSK!MTB"
        threat_id = "2147741175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 41 03 8a d0 8a d8 80 e2 f0 80 e3 fc c0 e2 02 0a 11 c0 e0 06 0a 41 02 c0 e3 04 0a 59 01 8b 4d f4 88 14 0f 47 88 1c 0f}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_BM_2147741577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.BM!MTB"
        threat_id = "2147741577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tekedulefukaranicayupalibu" ascii //weight: 1
        $x_1_2 = "zotayemepasesiyokihatini" ascii //weight: 1
        $x_1_3 = {b8 85 c5 0a 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_BS_2147741861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.BS!MTB"
        threat_id = "2147741861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 8b 45 e8 83 65 ec 00 03 c7 d3 ea 03 55 c4 33 d0 33 d6 8b 75 d0 2b f2 89 75 d0 c1 e3 0b}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d d8 8b d6 d3 ea 8b 4d e8 03 55 bc 8d 04 31 33 d8 81 3d ?? ?? ?? ?? c1 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_BB_2147744543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.BB!MTB"
        threat_id = "2147744543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CRYPTINTERNALDATA" ascii //weight: 10
        $x_10_2 = "$URL , $PATH" ascii //weight: 10
        $x_10_3 = "$TITLE , $BODY , $TYPE" ascii //weight: 10
        $x_10_4 = "( $RESNAME , $RESTYPE )" ascii //weight: 10
        $x_10_5 = "RUN ( @TEMPDIR &" ascii //weight: 10
        $x_10_6 = "PROCESSCLOSE ( @AUTOITPID )" ascii //weight: 10
        $x_10_7 = "FILEWRITE ( $VBSPATH , $VBS )" ascii //weight: 10
        $x_10_8 = "FILEWRITE ( $EXEPATH , $BYTES )" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_PA_2147744583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PA!MTB"
        threat_id = "2147744583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 ec 25 1b 07 d0 4d 81 6d ec 88 eb 73 22 bb 87 d5 7c 3a 81 45 ec 8c eb 73 22 8b 45 f8 8b 4d ec 8b d0 d3 e2 8b c8 c1 e9 05 03 4d ?? 03 55 ?? 89 35 ?? ?? ?? ?? 33 d1 8b 4d f4 03 c8 33 d1 29 55 f0 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 55 ec 25 1b 07 d0 4d 81 6d ec 88 eb 73 22 bb 87 d5 7c 3a 81 45 ec 8c eb 73 22 8b 4d ec 8b c7 d3 e0 8b cf c1 e9 05 03 4d ?? 03 45 ?? 89 15 ?? ?? ?? ?? 33 c1 8b 4d f4 03 cf 33 c1 29 45 f0 a1 ?? ?? ?? ?? 3d ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Predator_BC_2147744792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.BC!MTB"
        threat_id = "2147744792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "( $FILE , $STARTUP , $RES , $RUN =" ascii //weight: 10
        $x_10_2 = "( $TITLE , $BODY , $TYPE )" ascii //weight: 10
        $x_10_3 = "( $URL , $PATH )" ascii //weight: 10
        $x_10_4 = " = EXECUTE (" ascii //weight: 10
        $x_10_5 = "$DATA = READRESOURCES ( $RES ," ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_PB_2147745542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PB!MTB"
        threat_id = "2147745542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c8 81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 8a 84 15 ?? ?? ff ff 2a c1 88 84 15 ?? ?? ff ff 42 89 95 ?? ?? ff ff 8a 85 ?? ?? ff ff eb cc 05 00 83 fa ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be c0 25 0f 00 00 80 79 05 48 83 c8 f0 40 28 44 0d ?? 41 83 f9 ?? 73 05 8a 45 ?? eb e2}  //weight: 1, accuracy: Low
        $x_1_3 = {40 83 f8 0d 73 06 8a 4c 24 ?? eb f0 04 00 30 4c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_GJ_2147745836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.GJ!MTB"
        threat_id = "2147745836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5c 24 10 50 00 8b 4b 04 [0-4] 89 4c 24 04 [0-4] 8b 4b 08 [0-4] 89 4c 24 08 [0-4] 83 c3 0c [0-4] 89 5c 24 0c [0-4] 33 db 8b 54 24 0c [0-4] 8b 12 33 d3 [0-4] 3b 54 24 08 [0-4] 74 ?? [0-4] 43 [0-4] [0-4] eb ?? 89 5c 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {ff e2 8b 04 24 50 00 31 1c 0a [0-4] 3b 4c 24 04 [0-4] 7d ?? [0-4] [0-4] 83 c1 04 [0-4] eb ?? 8b e5 [0-4] 5d [0-4] 5b [0-4] ff e2 8b 04 24 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_GK_2147745840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.GK!MTB"
        threat_id = "2147745840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 dc 0f b6 82 98 b0 44 00 89 45 e0 8b 4d e0 f7 d1 89 4d e0 8b 55 e0 2b 55 dc 89 55 e0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d e0 03 4d dc 89 4d e0 8b 55 e0 f7 d2 89 55 e0 8b 45 e0 35 90 01 01 00 00 00 89 45 e0 8b 4d dc 8a 55 e0 88 91 90 01 03 00 e9 9a fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_PVD_2147747955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PVD!MTB"
        threat_id = "2147747955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d ?? ?? ?? ?? ac 10 00 00 56 a3 ?? ?? ?? ?? 8b f0 75 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_2 = {69 c0 fd 43 03 00 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_3 = {0f b6 84 15 b4 f8 ff ff 0f b6 c9 03 c8 0f b6 c1 0f b6 84 05 b4 f8 ff ff 30 84 3d bc f9 ff ff}  //weight: 2, accuracy: High
        $x_2_4 = {8b 45 08 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Predator_B_2147749172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.B!MTB"
        threat_id = "2147749172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cftp\\Ftplist.txt" ascii //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\DownloadManager\\Passwords\\" ascii //weight: 1
        $x_1_3 = "\\FTPGetter\\servers.xml" ascii //weight: 1
        $x_1_4 = "\\SmartFTP\\Client 2.0\\Favorites\\Quick Connect\\*.xml" ascii //weight: 1
        $x_1_5 = "WshShell.RegRead" ascii //weight: 1
        $x_1_6 = "\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_7 = "\\Trillian\\users\\global\\accounts.dat" ascii //weight: 1
        $x_1_8 = "\\Claws-mail" ascii //weight: 1
        $x_1_9 = "\\Apple Computer\\Preferences\\keychain.plist" ascii //weight: 1
        $x_1_10 = "com.apple.Safari" ascii //weight: 1
        $x_1_11 = "77bc582b-f0a6-4e15-4e80-61736b6f3b29" ascii //weight: 1
        $x_1_12 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_A_2147749173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.A!!Predator.gen!MTB"
        threat_id = "2147749173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "Predator: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cftp\\Ftplist.txt" ascii //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\DownloadManager\\Passwords\\" ascii //weight: 1
        $x_1_3 = "\\FTPGetter\\servers.xml" ascii //weight: 1
        $x_1_4 = "\\SmartFTP\\Client 2.0\\Favorites\\Quick Connect\\*.xml" ascii //weight: 1
        $x_1_5 = "WshShell.RegRead" ascii //weight: 1
        $x_1_6 = "\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_7 = "\\Trillian\\users\\global\\accounts.dat" ascii //weight: 1
        $x_1_8 = "\\Claws-mail" ascii //weight: 1
        $x_1_9 = "\\Apple Computer\\Preferences\\keychain.plist" ascii //weight: 1
        $x_1_10 = "com.apple.Safari" ascii //weight: 1
        $x_1_11 = "77bc582b-f0a6-4e15-4e80-61736b6f3b29" ascii //weight: 1
        $x_1_12 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_DHA_2147749896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.DHA!MTB"
        threat_id = "2147749896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 0c 73 18 8a 44 0d ?? 32 c2 f6 d0 88 44 0d 00 41 89 8d ?? ?? ?? ?? 8a 55 ?? eb e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_PVS_2147750846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PVS!MTB"
        threat_id = "2147750846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b ?? ?? ?? ?? ?? 75 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4d 08 30 04 0e 46 3b 75 0c 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 f4 fb ff ff 30 1c 30 46 3b 75 0c 0f 8c}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4c 24 40 30 04 0e 46 3b 74 24 44 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_5 = {69 c0 fd 43 03 00 83 ec 50 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_6 = {30 04 1e 46 3b f7 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_7 = {69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 a1 ?? ?? ?? ?? 89 45 fc 81 3d ?? ?? ?? ?? a5 02 00 00 75 2b 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_8 = {33 d8 8b 45 d0 03 45 d8 88 18 eb 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_BD_2147751800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.BD!MTB"
        threat_id = "2147751800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "( $FILE , $STARTUP , $RES , $RUN =" ascii //weight: 10
        $x_10_2 = "( $TITLE , $BODY , $TYPE " ascii //weight: 10
        $x_10_3 = "( $URL , $PATH " ascii //weight: 10
        $x_10_4 = " = EXECUTE (" ascii //weight: 10
        $x_10_5 = " = READRESOURCES ( $RES ," ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_AA_2147751835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AA!MTB"
        threat_id = "2147751835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Screenshot.jpeg" ascii //weight: 1
        $x_1_2 = "\\Foxmail.url.ma" ascii //weight: 1
        $x_1_3 = "Bcrypt.dll" ascii //weight: 1
        $x_1_4 = {0f b6 04 0f 33 c6 c1 ee 08 0f b6 c0 33 34 85 ?? ?? ?? ?? 47 3b fa 72 e8 f7 d6 5f 8b c6 5e c3}  //weight: 1, accuracy: Low
        $x_1_5 = {30 4c 05 f5 40 83 f8 0a 73 05 8a 4d f4 eb f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_MR_2147752089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.MR!MTB"
        threat_id = "2147752089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Dynamic R\\prjDynamicn.vbp" wide //weight: 1
        $x_1_2 = "DynamicSkin.exe" wide //weight: 1
        $x_1_3 = "5BcA44BbCAa4Ae5B6cDbB456cB6babc6Bae6DADbD5C6f5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_MS_2147752600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.MS!MTB"
        threat_id = "2147752600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 5f 5d c3 65 00 8b 02 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 e9 ?? 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 [0-25] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 [0-8] 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOCAL $ESDFQSD = EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_2 = "LOCAL $SFDQFSDFSD = $ESDFQSD ( \"binaryt\" & \"ostring\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( \"binaryt\" & \"ostring\" " ascii //weight: 1
        $x_1_2 = "= EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_3 = " = EXECUTE ( MTDUDAQCWRWM ( \"647964627475641\" ) )" ascii //weight: 1
        $x_1_4 = "EXECUTE ( STRINGREVERSE ( BINARYTOSTRING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RETURN EXECUTE ( $" ascii //weight: 1
        $x_10_2 = "= BINARY ( \"0x\" &" ascii //weight: 10
        $x_1_3 = "( $STRINPUT , \"" ascii //weight: 1
        $x_10_4 = "$RESULT = STRINGSPLIT ( $STRINPUT , \"\" )" ascii //weight: 10
        $x_1_5 = "$STRARRAY = STRINGSPLIT ( $STRINPUT , \"\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_AR_2147753147_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOCAL $ASAPGYANVLRLVFNXQXIYTGDHPQXGHIJINQGX = EXECUTE" ascii //weight: 1
        $x_1_2 = "$CUUSEVCIXNIRYDJHKISNSARPSQJZCMDBTUFGZMEJJI = $ASAPGYANVLRLVFNXQXIYTGDHPQXGHIJINQGX ( \"binarytostring\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE " ascii //weight: 1
        $x_1_2 = "( $URL , $PATH " ascii //weight: 1
        $x_1_3 = " = EXECUTE (" ascii //weight: 1
        $x_1_4 = " = READRESOURCES ( $RES ," ascii //weight: 1
        $x_2_5 = "( \"0x40486f6d654472697665202620225c" ascii //weight: 2
        $x_2_6 = "( \"0x4053797374656d446972202620225c" ascii //weight: 2
        $x_1_7 = "2e65786522\" , $" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_AR_2147753147_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= EXECUTE ( NBSCZZVCJSJT ( \"617C61677170614\" ) )" ascii //weight: 1
        $x_1_2 = "EXECUTE ( STRINGREVERSE ( BINARYTOSTRING ( NBSCZZVCJSJT (" ascii //weight: 1
        $x_1_3 = " ( \"binaryt\" & \"ostring\" )" ascii //weight: 1
        $x_1_4 = {20 00 4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {20 4c 4f 43 41 4c 20 24 [0-31] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 65 78 65 63 75 74 65 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 3f 00 4c 00 4f 00 43 00 41 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 58 45 43 55 54 45 3f 00 4c 4f 43 41 4c}  //weight: 1, accuracy: Low
        $x_1_3 = "( \"binarytostring\" )" ascii //weight: 1
        $x_1_4 = "0x42696E617279546F537472696E6728" ascii //weight: 1
        $x_1_5 = "0x436872572824" ascii //weight: 1
        $x_1_6 = "55626F756E6428247367737077616C6965656372636563616B69787365646F626E627A667679786F74736C786E617829202D20223122" ascii //weight: 1
        $x_1_7 = "55626F756E6428" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= EXECUTE ( \"execute\" )" ascii //weight: 2
        $x_2_2 = "OPT ( \"ExpandEnvStrings\" , 1 )" ascii //weight: 2
        $x_2_3 = "= REGREAD ( \"HKCR\\WLMail.Url.Mailto\\Shell\\open\\command\" , \"\" )" ascii //weight: 2
        $x_2_4 = "= RUN ( STRINGREPLACE" ascii //weight: 2
        $x_2_5 = "\"%1\" , _INETEXPLORERCAPABLE ( \"mailto:\" & $SMAILTO & \"?subject=\" & $SMAILSUBJECT & \"&body=\" & $SMAILBODY ) ) )" ascii //weight: 2
        $x_4_6 = "\"https://api.ipify.org\" ," ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_AR_2147753147_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AR!MTB"
        threat_id = "2147753147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0x446C6C43616C6C282761647661706933322E646C6C272C2027696E74272C2027536574536563757269747944657363726970746F724461636C2" ascii //weight: 1
        $x_1_2 = "0x446C6C5374727563744372656174652827627974655B32305D2729" ascii //weight: 1
        $x_1_3 = "0x446C6C43616C6C28226B65726E656C3332222C2022707472222C20225669727475616C416C6C6F63222C202264776F7264222C202230222C20" ascii //weight: 1
        $x_1_4 = {3d 00 20 00 44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 41 00 44 00 44 00 52 00 45 00 53 00 53 00 20 00 28 00 20 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 22 00 73 00 74 00 72 00 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 56 00 45 00 52 00 53 00 45 00 20 00 28 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 22 00 20 00 26 00 20 00 24 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 44 4c 4c 43 41 4c 4c 41 44 44 52 45 53 53 20 28 20 22 64 77 6f 72 64 22 20 2c 20 24 [0-31] 20 2c 20 22 73 74 72 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 53 54 52 49 4e 47 52 45 56 45 52 53 45 20 28 20 42 49 4e 41 52 59 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 22 20 26 20 24}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-5] 20 00 3d 00 20 00 24 00 [0-5] 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 56 00 45 00 52 00 53 00 45 00 20 00 28 00 20 00 22 00 67 00 6e 00 69 00 72 00 74 00 73 00 6f 00 74 00 79 00 72 00 61 00 6e 00 69 00 62 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {4c 4f 43 41 4c 20 24 [0-5] 20 3d 20 24 [0-5] 20 28 20 53 54 52 49 4e 47 52 45 56 45 52 53 45 20 28 20 22 67 6e 69 72 74 73 6f 74 79 72 61 6e 69 62 22 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Predator_2147753524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.MT!MTB"
        threat_id = "2147753524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 5f 5d c3 65 00 8b 02 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 e9 ?? 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 [0-20] 33 c1 ?? ?? c7 05 [0-20] 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_ARA_2147753575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.ARA!MTB"
        threat_id = "2147753575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 3f 00 4c 00 4f 00 43 00 41 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 58 45 43 55 54 45 3f 00 4c 4f 43 41 4c}  //weight: 1, accuracy: Low
        $x_1_3 = "( \"binarytostring\" )" ascii //weight: 1
        $x_1_4 = "\"0x537472696E6753706C6974" ascii //weight: 1
        $x_1_5 = "\"0x4173632824" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Predator_SS_2147754358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= @USERPROFILEDIR & " ascii //weight: 1
        $x_1_2 = "LOCAL $ESDFQSD = EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_3 = "0x2435666739366464662026204368725728426974584f522841\" & " ascii //weight: 1
        $x_1_4 = "0x537472696e6753706c69742824676635662c20222229\" ) )" ascii //weight: 1
        $x_1_5 = "= $ESDFQSD ( \"binaryt\" & \"ostring\" )" ascii //weight: 1
        $x_1_6 = "( \"0x42696e617279546f537472696e672822307822202620537472696e675472696d526967687428247a653838657a2c20312929\" ) )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_SS_2147754358_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $URL , $PATH )" ascii //weight: 1
        $x_2_2 = "SHELLEXECUTE (" ascii //weight: 2
        $x_1_3 = "307834663730373432383232353437323631373934393633366636653438363936343635" ascii //weight: 1
        $x_2_4 = "6202566796274456d6f68404x0" ascii //weight: 2
        $x_1_5 = "0x537472696E6753706C697428" ascii //weight: 1
        $x_1_6 = "0x426974584F5228" ascii //weight: 1
        $x_2_7 = "353236353730364336313633363532383234373636323733353036313734363832433230323235433232324332303232324632323239" ascii //weight: 2
        $x_1_8 = " = EXECUTE (" ascii //weight: 1
        $x_1_9 = " = READRESOURCES ( $RES ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_SS_2147754358_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "307834303533373436313732373437353730343436393732323032363230323235433232323032363230323436323632363232303236323032323245373537" ascii //weight: 2
        $x_1_2 = "PAYLOADEXIST" ascii //weight: 1
        $x_2_3 = "307832343636364636433634363537323435373836393733373432303344323034363631364337333635" ascii //weight: 2
        $x_1_4 = "= CHRW ( BITXOR ( ASC (" ascii //weight: 1
        $x_2_5 = "307832343735373236433435373836393733373432303344323034363631364337333635" ascii //weight: 2
        $x_1_6 = "( $URL , $PATH )" ascii //weight: 1
        $x_1_7 = "= EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_8 = "( \"binarytostring\" )" ascii //weight: 1
        $x_1_9 = "SLEEP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_SS_2147754358_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "3078343636393663363534663730363536653238323436363639366336353530363137343638326332303232333232323239" ascii //weight: 2
        $x_2_2 = "307835303732366636333635373337333435373836393733373437333238323433343634373337313636333437313733363436363634373332393230" ascii //weight: 2
        $x_2_3 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-37] 20 00 28 00 20 00 22 00 36 00 35 00 37 00 38 00 36 00 35 00 36 00 33 00 37 00 35 00 37 00 34 00 36 00 35 00 30 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {3d 20 45 58 45 43 55 54 45 20 28 20 [0-37] 20 28 20 22 36 35 37 38 36 35 36 33 37 35 37 34 36 35 30 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_1_5 = "= BINARYTOSTRING ( \"0x\" &" ascii //weight: 1
        $x_1_6 = "SLEEP ( \"" ascii //weight: 1
        $x_1_7 = "PAYLOADEXIST" ascii //weight: 1
        $x_1_8 = "= STRINGSPLIT (" ascii //weight: 1
        $x_1_9 = " $URL , $PATH )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_SS_2147754358_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOCAL $ESDFQSD = EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_2 = "0x2435666739366464662026204368725728426974584f522841\" & " ascii //weight: 1
        $x_1_3 = "0x537472696e6753706c69742824676635662c20222229\" ) )" ascii //weight: 1
        $x_1_4 = "= $ESDFQSD ( \"binaryt\" & \"ostring\" )" ascii //weight: 1
        $x_1_5 = "( \"0x42696e617279546f537472696e672822307822202620537472696e675472696d526967687428247a653838657a2c20312929\" ) )" ascii //weight: 1
        $x_1_6 = "( \"226578652E646C697542534D5C37323730352E302E32765C6B726F77656D6172465C54454E2E74666F736F7263694D5C73776F646E69575C22202620" ascii //weight: 1
        $x_1_7 = "= AA ( \"activedsN\" , \"2\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Predator_SS_2147754358_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "307834303534363536443730343436393732323032363230343336383732323833393332323932303236323032343636363936433635" ascii //weight: 4
        $x_1_2 = " = EXECUTE (" ascii //weight: 1
        $x_2_3 = "= REGREAD ( \"HKCR\\WLMail.Url.Mailto\\Shell\\open\\command\" , \"\" )" ascii //weight: 2
        $x_2_4 = "307834343643364335333734373237353633373434333732363536313734363532383232363237393734363535423232323032363230" ascii //weight: 2
        $x_1_5 = "= STRINGREGEXP ( BINARYTOSTRING ( $SRETURN ) , \"((?:\\d{1,3}\\.){3}\\d{1,3})" ascii //weight: 1
        $x_1_6 = "= READRESOURCES ( $RES" ascii //weight: 1
        $x_1_7 = "= STRINGREPLACE ( $STEMPDATE , \"/\" , $STEMPSTRING" ascii //weight: 1
        $x_1_8 = " $URL , $PATH )" ascii //weight: 1
        $x_1_9 = "( $TITLE , $BODY , $TYPE " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_SS_2147754358_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "30783432363936453631373237393534364635333734373236393645363732383234363437313636373333343636373336343239" ascii //weight: 1
        $x_1_2 = "= EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_3 = "307834343643364335333734373237353633373434373635373435303734373232383234363733343636373333343637373137333335333436343239" ascii //weight: 1
        $x_1_4 = "307835333638363536433643343537383635363337353734363532383232363336443634323232433230323232303246363332303534363936443635" ascii //weight: 1
        $x_1_5 = "30783444373336373432364637383238323437343739373036353243323032343734363937343643363532433230323436323646363437393239" ascii //weight: 1
        $x_1_6 = "307834363639364336353537373236393734363532383234363636383631364536343643363532433230343436433643353337343732373536333734343736" ascii //weight: 1
        $x_1_7 = "324632323230323632303533373437323639364536373532363537303643363136333635323832343736363237333530363137343638324332303232354332" ascii //weight: 1
        $x_1_8 = "PAYLOADEXIST" ascii //weight: 1
        $x_1_9 = "= STRINGSPLIT (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Predator_SS_2147754358_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_2 = "( \"binarytostring\" )" ascii //weight: 1
        $x_5_3 = "307835303732366636333635373337333435373836393733373437333238323433343634373337313636333437313733363436363634373332" ascii //weight: 5
        $x_1_4 = "307834343643364335333734373237353633373434333732363536313734363532383232363237393734363535423232323032363230343236393645363137" ascii //weight: 1
        $x_1_5 = "PAYLOADEXIST" ascii //weight: 1
        $x_1_6 = "= STRINGSPLIT (" ascii //weight: 1
        $x_1_7 = "307834363639364336353435373836393733373437333238323436343639373232390" ascii //weight: 1
        $x_1_8 = "3078323437363632373334353738363937333734323033443230343636313643373336350" ascii //weight: 1
        $x_1_9 = "3078323437353732364334353738363937333734323033443230343636313643373336350" ascii //weight: 1
        $x_1_10 = "307834363639364336353537373236393734363532383234373537323643353036313734363832433230323437353732364334333646364537343635364537" ascii //weight: 1
        $x_1_11 = "3078343636393663363534663730363536653238323436363639366336353530363137343638326332303232333232323239" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_SS_2147754358_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SS!MTB"
        threat_id = "2147754358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0x2464736B6A202620225C22202620246935753667643437202620222E65786522" ascii //weight: 1
        $x_1_2 = "0x2464736B6A202620225C2220262024666B6A63202620222E76627322" ascii //weight: 1
        $x_1_3 = "0x46696C65526561642846696C654F70656E28404175746F49744578652C20223136333834222929" ascii //weight: 1
        $x_1_4 = "0x22536574205773685368656C6C203D20575363726970742E4372656174654F626A65637428222026202464733435733820262022575363726970742E" ascii //weight: 1
        $x_1_5 = "0x4053746172747570446972202620225C22202620537472696E675265706C6163652824666B6A632C20222E766273222C20222E75726C222920262022" ascii //weight: 1
        $x_1_6 = "0x225B496E7465726E657453686F72746375745D222026204043522026202255524C3D66696C653A2F2F2F22202620247064666A6B697250617468" ascii //weight: 1
        $x_1_7 = "0x4054656D70446972202620225C222026202466647335673664366434666734647366" ascii //weight: 1
        $x_1_8 = "= EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_9 = "0x52756E2824666473356736643664346667346473663129" ascii //weight: 1
        $x_1_10 = "0x46696C65577269746528247064666A6B6972506174682C20247064666A6B697229" ascii //weight: 1
        $x_1_11 = "0x446972437265617465282464736B6A29" ascii //weight: 1
        $x_1_12 = "0x537472696e67526576657273652842696e617279546f537472" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_SM_2147754372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SM!MTB"
        threat_id = "2147754372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogInfo.txt" ascii //weight: 1
        $x_1_2 = "\\passwords.txt" ascii //weight: 1
        $x_1_3 = "Installed Software.txt" ascii //weight: 1
        $x_1_4 = "\\forms.txt" ascii //weight: 1
        $x_1_5 = "Crypto Wallets\\WalletInfo.txt" ascii //weight: 1
        $x_1_6 = "Application Data\\Authy Desktop\\Local Storage\\*.localstorage" ascii //weight: 1
        $x_1_7 = "\\NordVPN\\NordVPN*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_SM_2147754372_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SM!MTB"
        threat_id = "2147754372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0x4f707428225472617949636f6e48696465222c2022312229" ascii //weight: 1
        $x_2_2 = "0x5368656C6C45786563757465284054656D70446972202620225C22202620247061746829" ascii //weight: 2
        $x_1_3 = "= EXECUTE (" ascii //weight: 1
        $x_1_4 = "0x5368656c6c45786563757465282466696c655061746829" ascii //weight: 1
        $x_2_5 = "0x405573657250726F66696C65446972202620225C222026" ascii //weight: 2
        $x_1_6 = "0x46696C65577269746528" ascii //weight: 1
        $x_1_7 = "46696C65526561642846696C654F70656E284053637269707446756C6C50617468" ascii //weight: 1
        $x_1_8 = " = STRINGREPLACE ( " ascii //weight: 1
        $x_1_9 = " = READRESOURCES ( $RES ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_XC_2147754961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.XC!MTB"
        threat_id = "2147754961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE " ascii //weight: 1
        $x_1_2 = "( $URL , $PATH " ascii //weight: 1
        $x_1_3 = " = EXECUTE (" ascii //weight: 1
        $x_1_4 = " = READRESOURCES ( $RES ," ascii //weight: 1
        $x_1_5 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 3f 00 4c 00 4f 00 43 00 41 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 45 58 45 43 55 54 45 3f 00 4c 4f 43 41 4c}  //weight: 1, accuracy: Low
        $x_1_7 = "( \"binarytostring\" )" ascii //weight: 1
        $x_1_8 = "0x42696E617279546F537472696E6728" ascii //weight: 1
        $x_1_9 = "0x436872572824" ascii //weight: 1
        $x_1_10 = "55626F756E6428" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_Win32_Predator_AV_2147755533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.AV!MTB"
        threat_id = "2147755533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 20 00 22 00 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 2e 65 78 65 22 20 2c 20 40 53 43 52 49 50 54 44 49 52 20 26 20 22 5c [0-30] 2e 65 78 65 22 20 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "SLEEP (" ascii //weight: 1
        $x_10_4 = {49 00 46 00 20 00 46 00 49 00 4c 00 45 00 45 00 58 00 49 00 53 00 54 00 53 00 20 00 28 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00 20 00 54 00 48 00 45 00 4e 00 20 00 46 00 49 00 4c 00 45 00 4d 00 4f 00 56 00 45 00 20 00 28 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 24 00}  //weight: 10, accuracy: Low
        $x_10_5 = {49 46 20 46 49 4c 45 45 58 49 53 54 53 20 28 20 40 53 43 52 49 50 54 44 49 52 20 26 20 22 5c [0-30] 2e 65 78 65 22 20 29 20 54 48 45 4e 20 46 49 4c 45 4d 4f 56 45 20 28 20 40 53 43 52 49 50 54 44 49 52 20 26 20 22 5c 00 2e 65 78 65 22 20 2c 20 24}  //weight: 10, accuracy: Low
        $x_1_6 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {52 55 4e 20 28 20 40 53 43 52 49 50 54 44 49 52 20 26 20 22 5c [0-30] 2e 65 78 65 22 20 2c 20 40 53 43 52 49 50 54 44 49 52 20 29}  //weight: 1, accuracy: Low
        $x_10_8 = {47 00 45 00 54 00 20 00 28 00 20 00 22 00 48 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 22 00 20 00 26 00 20 00 24 00 55 00 52 00 4c 00 20 00 26 00 20 00 22 00 2f 00 [0-15] 2f 00 [0-15] 2e 00 74 00 78 00 74 00 22 00 20 00 2c 00 20 00 40 00}  //weight: 10, accuracy: Low
        $x_10_9 = {47 45 54 20 28 20 22 48 74 74 70 3a 2f 2f 22 20 26 20 24 55 52 4c 20 26 20 22 2f [0-15] 2f [0-15] 2e 74 78 74 22 20 2c 20 40}  //weight: 10, accuracy: Low
        $x_1_10 = "$URL = \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_JK_2147755775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.JK!MTB"
        threat_id = "2147755775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE" ascii //weight: 1
        $x_1_2 = "$URL , $PATH )" ascii //weight: 1
        $x_1_3 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_4 = "3078353336383635366336633435373836353633373537343635323832343636363936633635353036313734363832390" ascii //weight: 1
        $x_1_5 = "307834363639364336353433364336463733363532383234363636383631364536343643363532390" ascii //weight: 1
        $x_1_6 = "3078343035343635364437303434363937323230323632303433363837323238333933323239323032363230323436363639364336350" ascii //weight: 1
        $x_1_7 = "3078323437353732364334353738363937333734323033443230343636313643373336350" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_JK_2147755775_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.JK!MTB"
        threat_id = "2147755775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE" ascii //weight: 1
        $x_1_2 = "$URL , $PATH )" ascii //weight: 1
        $x_1_3 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_4 = "30783234373036313739364336463631363434353738363937333734323033443230343636313643373336350" ascii //weight: 1
        $x_1_5 = "30783436363936433635343537383639373337343733323832343730363137393643364636313634353036313734363832390" ascii //weight: 1
        $x_1_6 = "3078343936453635373434373635373432383234353535323443324332303430353436353644373034343639373232303236323032323543323232" ascii //weight: 1
        $x_1_7 = "3078353336383635364336433435373836353633373537343635323832323633364436343232324332303232323032463633323035" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Predator_JK_2147755775_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.JK!MTB"
        threat_id = "2147755775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE" ascii //weight: 1
        $x_1_2 = "$URL , $PATH )" ascii //weight: 1
        $x_1_3 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_4 = "30783436363936433635343537383639373337343733323832343730363137393643364636313634353036313734363832390" ascii //weight: 1
        $x_1_5 = "307834303535373336353732353037323646363636393643363534343639373232303236323032323543323232303236323032343632363236320" ascii //weight: 1
        $x_1_6 = "0x42696E617279546F537472696E672822307822202620537472696E675472696D5269676874282467686664736764662C20312929" ascii //weight: 1
        $x_1_7 = "307834303533363337323639373037343434363937320" ascii //weight: 1
        $x_1_8 = "3078343035333734363137323734373537303434363937323230323632303232354332323230" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_JK_2147755775_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.JK!MTB"
        threat_id = "2147755775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE" ascii //weight: 1
        $x_1_2 = "$URL , $PATH )" ascii //weight: 1
        $x_1_3 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_4 = "3078353336383635366336633435373836353633373537343635323832343636363936633635353036313734363832390" ascii //weight: 1
        $x_1_5 = "307834363639364336353433364336463733363532383234363636383631364536343643363532390" ascii //weight: 1
        $x_1_6 = "30783436363936633635346637303635366532383234363636393663363535303631373436383263323032323332323232390" ascii //weight: 1
        $x_1_7 = "307834303535373336353732353037323646363636393643363534343639373232303236323032323543323232303236323032343632363236320" ascii //weight: 1
        $x_1_8 = "30783530373236463633363537333733343336433646373336353238343034313735373436463439373435303439343432390" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Predator_JL_2147756360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.JL!MTB"
        threat_id = "2147756360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $TITLE , $BODY , $TYPE" ascii //weight: 1
        $x_1_2 = "$URL , $PATH )" ascii //weight: 1
        $x_1_3 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_4 = "334432303537353336333732363937303734324534333732363536313734363534463632364136353633373432383232323032363230" ascii //weight: 1
        $x_1_5 = "307834363639364336353435373836393733373437333238323436343639373232390" ascii //weight: 1
        $x_1_6 = "3730363137393643364636313634353036313734363832303236323034333638373232383333333432393230323632303433363837323238333333" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_PRB_2147756377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PRB!MTB"
        threat_id = "2147756377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "3078343936453635373434373635373432383234353535323443324332303430353436353644373034343639373232303236323032323543323232303" ascii //weight: 3
        $x_3_2 = "3078343035333734363137323734373537303434363937323230323632303232354332323230323632303234363236323632323032363230323232453" ascii //weight: 3
        $x_3_3 = "3078323235423439364537343635373236453635373435333638364637323734363337353734354432323230323632303430343335323230323632303" ascii //weight: 3
        $x_1_4 = "$PAYLOADEXIST" ascii //weight: 1
        $x_1_5 = "STRINGSPLIT ( $THCPLGRKALJXFZPDKMWEPEPHFVWFZXUSWSNBFTEHVFHWFEERN" ascii //weight: 1
        $x_1_6 = "CHRW ( BITXOR ( ASC" ascii //weight: 1
        $x_1_7 = "STRINGREPLACE" ascii //weight: 1
        $x_1_8 = "( $URL , $PATH )" ascii //weight: 1
        $x_1_9 = "( $FILE , $RES )" ascii //weight: 1
        $x_3_10 = "3078343636393663363535373732363937343635323832343730363137393663366636313634353036313734363832633230343636393663363535323" ascii //weight: 3
        $x_1_11 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_12 = "EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_13 = "binarytostring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_PRR_2147756835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PRR!MTB"
        threat_id = "2147756835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "binarytostring" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_3 = "READRESOURCES ( $RES" ascii //weight: 1
        $x_1_4 = "( $FILE , $RES )" ascii //weight: 1
        $x_10_5 = "3078343035343635364437303434363937323230323632303433363837323238333933323239323032363230323436363639364336350\" )" ascii //weight: 10
        $x_1_6 = "CHRW ( BITXOR ( ASC" ascii //weight: 1
        $x_1_7 = "STRINGSPLIT ( $THCPLGRKALJXFZPDKMWEPEPHFVWFZXUSWSNBFTEHVFHWFEERN" ascii //weight: 1
        $x_10_8 = "3078323436343639373232303236323032323543323232303236323032343631363136310\" )" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_PRV_2147756844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.PRV!MTB"
        threat_id = "2147756844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $URL , $PATH )" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"execute\" )" ascii //weight: 1
        $x_1_3 = "STRINGSPLIT (" ascii //weight: 1
        $x_2_4 = "3078323436343639373232303236323032323543323232303236323032343631363136310" ascii //weight: 2
        $x_2_5 = "3078323436343639373232303236323032323543323232303236323032343632363236323230323632303232324537363632373332320" ascii //weight: 2
        $x_2_6 = "307834303533373436313732373437353730343436393732323032363230323235433232323032363230323436323632363232303236323032323245373537" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_YA_2147757702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.YA!MTB"
        threat_id = "2147757702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIM $PAYLOADEXIST" ascii //weight: 1
        $x_2_2 = "EXECUTE (" ascii //weight: 2
        $x_1_3 = "$URL , $PATH )" ascii //weight: 1
        $x_2_4 = "CHRW ( BITXOR ( ASC " ascii //weight: 2
        $x_2_5 = "30783434364336433433363136433643323832323642363537323645363536433333333232323243323032323" ascii //weight: 2
        $x_1_6 = "STRINGREPLACE ( \"woinss\" , \"x\" , \"y\" )" ascii //weight: 1
        $x_1_7 = "CWMLEXPISM ( $O , \"JMMDKQLEFV\" , \"9\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Predator_SO_2147765675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SO!!Predator.SO!MTB"
        threat_id = "2147765675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "Predator: an internal category used to refer to some threats"
        info = "SO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogInfo.txt" ascii //weight: 1
        $x_1_2 = "\\passwords.txt" ascii //weight: 1
        $x_1_3 = "Installed Software.txt" ascii //weight: 1
        $x_1_4 = "\\forms.txt" ascii //weight: 1
        $x_1_5 = "Crypto Wallets\\WalletInfo.txt" ascii //weight: 1
        $x_1_6 = "Application Data\\Authy Desktop\\Local Storage\\*.localstorage" ascii //weight: 1
        $x_1_7 = "\\NordVPN\\NordVPN*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_EDS_2147780656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.EDS!MTB"
        threat_id = "2147780656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 84 24 04 04 00 00 56 33 f6 85 ff 7e 6f 55 8b 6c 24 08 81 ff 85 02 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {30 04 33 81 ff 91 05 00 00 75 2e 6a 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_EQW_2147780658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.EQW!MTB"
        threat_id = "2147780658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 4c 01 15 8b 35 ?? ?? ?? ?? 88 0c 06 8b 0d ?? ?? ?? ?? 81 f9 03 02 00 00 75 06}  //weight: 10, accuracy: Low
        $x_5_2 = "IsProcessorFeaturePresent" ascii //weight: 5
        $x_5_3 = "IsDebuggerPresent" ascii //weight: 5
        $x_5_4 = {81 fe 2b ac 01 00 7f 09 46 81 fe ba 2d bc 1e 7c d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_SSM_2147792893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SSM!MTB"
        threat_id = "2147792893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 4c 4f 42 41 4c 20 24 51 33 30 33 38 58 50 20 3d 20 45 58 45 43 55 54 45 0d 0a 20 44 49 4d 20 24 54 33 31 38 52 44 20 3d 20 24 51 33 30 33 38 58 50 20 28 20 22 43 68 72 22 20 29}  //weight: 1, accuracy: High
        $x_1_2 = "DIM $B32303630U61OEHE = $Q3038XP ( $T318RD ( 272 + -204 ) & $T318RD ( 312 + -204 ) & $T318RD ( 312 + -204 )" ascii //weight: 1
        $x_1_3 = "DLLCALLADDRESS ( $T318RD ( 314 + -204 ) & $T318RD ( 315 + -204 ) & $T318RD ( 314 + -204 ) & $T318RD ( 305 + -204 )" ascii //weight: 1
        $x_1_4 = "$O32313332Y3S = $O32313332Y3S [ 0 ]" ascii //weight: 1
        $x_1_5 = "$N33MMDB &= $T318RD ( 260 + -204 ) & $T318RD ( 302 + -204 ) & $T318RD ( 256 + -204 ) & $T318RD ( 259 + -204 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_SSM_2147792893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.SSM!MTB"
        threat_id = "2147792893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 4c 4f 42 41 4c 20 24 57 33 30 33 55 46 38 4c 20 3d 20 45 58 45 43 55 54 45 0d 0a 20 44 49 4d 20 24 42 33 31 53 4a 4a 4c 20 3d 20 24 57 33 30 33 55 46 38 4c 20 28 20 22 43 68 72 22 20 29}  //weight: 1, accuracy: High
        $x_1_2 = "$U3230393804C ( $J32313837DHOKXTRJ , $B31SJJL ( 319 + -204 ) & $B31SJJL ( 308 + -204 ) & $B31SJJL ( 305 + -204 )" ascii //weight: 1
        $x_1_3 = "$B31SJJL ( 312 + -204 ) & $B31SJJL ( 303 + -204 ) & $B31SJJL ( 315 + -204 ) & $B31SJJL ( 304 + -204 ) & $B31SJJL ( 305 + -204 )" ascii //weight: 1
        $x_1_4 = "DLLCALLADDRESS ( $B31SJJL ( 314 + -204 ) & $B31SJJL ( 315 + -204 ) & $B31SJJL ( 314 + -204 ) & $B31SJJL ( 305 + -204 )" ascii //weight: 1
        $x_1_5 = "$D32313237VNV = $D32313237VNV [ 0 ]" ascii //weight: 1
        $x_1_6 = "DIM $Y32313136JL = $W303UF8L ( $B31SJJL ( 270 + -204 ) & $B31SJJL ( 309 + -204 ) & $B31SJJL ( 314 + -204 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_CB_2147816307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.CB!MTB"
        threat_id = "2147816307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zeroxero.dll" wide //weight: 1
        $x_1_2 = "HiIamMutex" wide //weight: 1
        $x_1_3 = "dserf.exe" wide //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_RPW_2147824773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.RPW!MTB"
        threat_id = "2147824773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 45 66 89 45 a2 58 6a 55 66 89 45 b0 58 6a 69 66 89 45 b2 58 6a 56 66 89 45 b4 58 6a 6e 66 89 45 b6 58 66 89 45 b8 6a 42 58 66 89 45 ba 6a 71 58 66 89 45 bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_RPY_2147892990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.RPY!MTB"
        threat_id = "2147892990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6a 0e 8d 45 ec 83 c1 0e 50 57 89 4d ee ff d6 6a 00 8d 45 0c 50 8b 43 20 8d 04 85 28 00 00 00 50 53 57 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Predator_EFG_2147896068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Predator.EFG!MTB"
        threat_id = "2147896068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GetLogicalDriveStringsW" ascii //weight: 3
        $x_3_2 = "IsValidLocale" ascii //weight: 3
        $x_3_3 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_4 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_5 = "FMessageLoop" ascii //weight: 3
        $x_3_6 = "RenExitInstance" ascii //weight: 3
        $x_3_7 = "RenInitInstance" ascii //weight: 3
        $x_3_8 = "FlushFileBuffers" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

