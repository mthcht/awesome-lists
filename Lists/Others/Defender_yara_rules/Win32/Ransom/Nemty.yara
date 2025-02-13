rule Ransom_Win32_Nemty_A_2147742141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.A!MTB"
        threat_id = "2147742141"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TDS_Trillium_Security_File_Protector_Projec" wide //weight: 1
        $x_1_2 = "Microsoft Enhanced RSA and AES Cryptographic Provider" wide //weight: 1
        $x_1_3 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" wide //weight: 1
        $x_1_4 = "*VIRTUAL*" wide //weight: 1
        $x_1_5 = "*VMWARE*" wide //weight: 1
        $x_1_6 = "*VBOX*" wide //weight: 1
        $x_1_7 = "*QEMU*" wide //weight: 1
        $x_1_8 = "Can't save data to file!" wide //weight: 1
        $x_1_9 = "Can't execute file!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_Win32_Nemty_A_2147742141_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.A!MTB"
        threat_id = "2147742141"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEMTY-DECRYPT.txt" ascii //weight: 1
        $x_1_2 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default}" ascii //weight: 1
        $x_1_3 = "https://pbs.twimg.com/media/Dn4vwaRW0AY-tUu.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_C_2147742387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.C"
        threat_id = "2147742387"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 44 24 10 ?? ?? ?? ?? b8 ?? ?? ?? ?? 81 44 24 10 ?? ?? ?? ?? 81 44 24 10 ?? ?? ?? ?? 81 e3 72 bf b9 21 81 6c 24 10 ?? ?? ?? ?? 81 44 24 10 ?? ?? ?? ?? b8 00 b4 f7 0d 81 44 24 10 ?? ?? ?? ?? c1 e8 07 81 44 24 10 ?? ?? ?? ?? c1 e0 18 25 ?? ?? ?? ?? 83 44 24 10 02 8b 44 24 10 0f af c6 8d 0c 85 ?? ?? ?? ?? 03 cd e8 ?? ?? ?? ?? 46 3b f7 72 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_PA_2147742602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PA!MTB"
        threat_id = "2147742602"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\nemty.exe" ascii //weight: 1
        $x_1_2 = "-DECRYPT.txt" ascii //weight: 1
        $x_1_3 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "fuckav" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_D_2147742810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.D"
        threat_id = "2147742810"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NEMTY" ascii //weight: 2
        $x_2_2 = "DECRYPT.txt" ascii //weight: 2
        $x_2_3 = "fuckav" ascii //weight: 2
        $x_2_4 = "/c vssadmin.exe delete shadows" ascii //weight: 2
        $x_2_5 = "wmic shadowcopy delete" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Nemty_PF_2147743822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PF!MTB"
        threat_id = "2147743822"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 04 00 00 00 6b c2 00 8b 4d ec 8b 14 01 89 55 d4 b8 04 00 00 00 c1 e0 00 8b 4d ec 8b 14 01 89 55 ?? b8 04 00 00 00 d1 e0 8b 4d ec 8b 14 01 89 55 ?? 81 3d ?? ?? ?? ?? 85 0f 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 55 fc 88 55 ff 0f b6 45 ff c1 e0 04 88 45 ff 0f b6 4d ff 81 e1 c0 00 00 00 88 4d ff 0f b6 55 fd 0f b6 45 ff 0b d0 88 55 fd 81 3d ?? ?? ?? ?? 7b 0e 00 00 75 0a 00 c7 05 ?? ?? ?? ?? 60 5a 20 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_PG_2147743942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PG!MTB"
        threat_id = "2147743942"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d0 05 b8 00 00 00 8b c8 c1 e9 04 83 e1 0f c1 e0 04 0b c8 81 e1 ff 00 00 00 f7 d1 2b ca 33 ca 2b ca 8b c1 c1 e8 06 83 e0 03 c1 e1 02 0b c1 83 f0 1a 25 ff 00 00 00 33 c2 8b c8 d1 e9 80 e1 7f c0 e0 07 0a c8 88 8a ?? ?? ?? ?? 42 81 fa ?? ?? 00 00 72 0e 00 0f b6 82 ?? ?? ?? ?? 8d 84 10}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8a 81 ?? ?? ?? ?? f7 d0 48 8b d0 83 e0 01 d1 ea 83 e2 7f c1 e0 07 0b d0 f7 d2 33 d1 8d 44 0a 1f f7 d0 35 c0 00 00 00 8d 54 48 01 f7 d2 8d 44 0a 30 88 81 e0 20 46 00 41 81 f9 ?? ?? 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Nemty_PH_2147749183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PH!MTB"
        threat_id = "2147749183"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8c 24 80 00 00 00 8b 54 24 18 8b 44 24 10 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 74 24 18 c1 ee 05 03 b4 24 ?? 00 00 00 03 d9 03 c2 33 d8 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 2b fe c7 44 24 ?? 00 00 00 00 81 f3 ?? ?? ?? ?? 81 6c 24 14 ?? ?? ?? ?? b8 ?? ?? ?? ?? 81 6c 24 14 ?? ?? ?? ?? 81 44 24 14 ?? ?? ?? ?? 8b 4c 24 14 8b f7 d3 e6 03 74 24 78 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d7 c1 ea 05 03 54 24 70 33 d0 33 d6 29 54 24 18 8b 44 24 74 29 44 24 10 83 6c 24 68 01 0f 85 74 fb ff ff 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_PI_2147750980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PI!MSR"
        threat_id = "2147750980"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEMTY_PRIVATE" ascii //weight: 1
        $x_1_2 = "Software\\NEMTY\\" ascii //weight: 1
        $x_1_3 = "recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete" ascii //weight: 1
        $x_1_4 = "-DECRYPT.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Nemty_PI_2147752802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PI!MTB"
        threat_id = "2147752802"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEMTY" ascii //weight: 1
        $x_1_2 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_3 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_4 = "-DECRYPT.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_PJ_2147752843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.PJ!MTB"
        threat_id = "2147752843"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".NEPHILIM" wide //weight: 1
        $x_1_2 = "NEPHILIM-DECRYPT.txt" wide //weight: 1
        $x_1_3 = {2e 00 65 00 78 00 65 00 00 00 00 00 2e 00 6c 00 6f 00 67 00 00 00 00 00 2e 00 63 00 61 00 62 00 00 00 00 00 2e 00 63 00 6d 00 64 00 00 00 00 00 2e 00 63 00 6f 00 6d 00 00 00 00 00 2e 00 63 00 70 00 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "SystemFunction036" ascii //weight: 1
        $x_1_5 = "PathFindExtensionW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_MMV_2147752847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.MMV!MTB"
        threat_id = "2147752847"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 3a 58 66 89 45 ee 6a 5c 58 66 89 45 ?? 33 c0 66 89 45 ?? 8d 45 ec 83 c1 ?? 50 66 89 4d ?? ff 15 ?? ?? ?? ?? 6a 04 57 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = "6NEPHILIM-DECRYPT.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nemty_AA_2147754559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.AA!MTB"
        threat_id = "2147754559"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NEMTY" ascii //weight: 10
        $x_10_2 = "DECRYPT.txt" wide //weight: 10
        $x_10_3 = "Your files were encrypted!" ascii //weight: 10
        $x_2_4 = "%compname%" ascii //weight: 2
        $x_2_5 = "%fileid%" ascii //weight: 2
        $x_2_6 = "%username%" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Nemty_AR_2147756365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemty.AR!MTB"
        threat_id = "2147756365"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\virubim_eshky.jpg" ascii //weight: 10
        $x_10_2 = "SIGARETA-RESTORE.txt" ascii //weight: 10
        $x_10_3 = "\\Release\\SIGARETA.pdb" ascii //weight: 10
        $x_1_4 = ".SIGARETA" ascii //weight: 1
        $x_1_5 = "program files (x86)" ascii //weight: 1
        $x_1_6 = "4372797074496D706F72744B6579" ascii //weight: 1
        $x_1_7 = "pohui" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

