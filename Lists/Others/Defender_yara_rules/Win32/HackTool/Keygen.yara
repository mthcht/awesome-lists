rule HackTool_Win32_Keygen_2147593794_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Keygen by PARADOX" ascii //weight: 3
        $x_1_2 = "Stop/Play Music" ascii //weight: 1
        $x_1_3 = "Generate CD-Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Keygen_2147593794_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.dayanzai.me" ascii //weight: 1
        $x_4_2 = "Corel Products Keygen" ascii //weight: 4
        $x_1_3 = "Software\\ASProtect\\Key" ascii //weight: 1
        $x_1_4 = "aspr_keys.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Keygen_2147593794_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Autodesk Products" wide //weight: 1
        $x_1_2 = "Extended Module: Chipex2" ascii //weight: 1
        $x_1_3 = "FastTracker v2.00 " ascii //weight: 1
        $x_1_4 = "MicroXm By Mr Gamer" ascii //weight: 1
        $x_1_5 = "Created By MrGam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "License file generated!" ascii //weight: 1
        $x_1_2 = "[ SFX by ghidorah ]" ascii //weight: 1
        $x_1_3 = "File successfully patched!" ascii //weight: 1
        $x_1_4 = "ghidorah@musician.org" ascii //weight: 1
        $x_1_5 = "http://www.CollakeSoftware.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Raiden ! Lz0" ascii //weight: 1
        $x_1_2 = "SERIAL" ascii //weight: 1
        $x_1_3 = "Generate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_5
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Code and Keygen" ascii //weight: 1
        $x_1_2 = "criminally insane" ascii //weight: 1
        $x_1_3 = "GFX: kR8ViTy/CRO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_6
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TEAM ZWT" ascii //weight: 2
        $x_1_2 = "You have been traced" ascii //weight: 1
        $x_1_3 = "Keymaker for" ascii //weight: 1
        $x_1_4 = "&Generate" ascii //weight: 1
        $x_1_5 = "&Quit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_7
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.embarcadero.EaseUS_DRW" ascii //weight: 2
        $x_1_2 = "TDCP_hash" ascii //weight: 1
        $x_1_3 = "DCPcrypt2" ascii //weight: 1
        $x_1_4 = "MustActivateSysMenu" ascii //weight: 1
        $x_1_5 = "EaseUS_DRW.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Keygen_2147593794_8
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Corel Products Keygen" ascii //weight: 1
        $x_1_2 = "Keygen" ascii //weight: 1
        $x_1_3 = "Activation Code" ascii //weight: 1
        $x_1_4 = "\\Corel\\StubFramework\\VSP" ascii //weight: 1
        $x_1_5 = "FCorelDrawX8Activation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_9
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NCH Software Keygen" ascii //weight: 1
        $x_1_2 = "Keygen.exe" ascii //weight: 1
        $x_1_3 = "secure.nch.com.au" ascii //weight: 1
        $x_1_4 = "www.nchsoftware.com" ascii //weight: 1
        $x_1_5 = "RadiXX11" ascii //weight: 1
        $x_1_6 = "Patch Hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_10
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keygenned by KaiZer SoZe" ascii //weight: 1
        $x_1_2 = "GfX done By fStD/cRo" ascii //weight: 1
        $x_1_3 = "Press Calculate Button" ascii //weight: 1
        $x_1_4 = "Enter Your Name" ascii //weight: 1
        $x_1_5 = "keygen" ascii //weight: 1
        $x_1_6 = "XMMOD" ascii //weight: 1
        $x_1_7 = "MUSIC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win32_Keygen_2147593794_11
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "write_disk_file" ascii //weight: 1
        $x_2_2 = "load_patcher" ascii //weight: 2
        $x_1_3 = "SearchAndReplace" ascii //weight: 1
        $x_2_4 = "<description>Patch</description>" ascii //weight: 2
        $x_1_5 = "GetPatcherWindowHandle" ascii //weight: 1
        $x_2_6 = "dup2patcher.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Keygen_2147593794_12
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen"
        threat_id = "2147593794"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keil Generic Keygen - EDGE" ascii //weight: 1
        $x_1_2 = "WELCOME TO ANOTHER NICE KEYGEN FROM YOUR FRIENDS AT EDGE" ascii //weight: 1
        $x_1_3 = "Gen. Serial" ascii //weight: 1
        $x_1_4 = "License Details" ascii //weight: 1
        $x_1_5 = "Nice music composed by " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Win32_Keygen_2147743020_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MSR"
        threat_id = "2147743020"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EaseUS_DRW.exe" ascii //weight: 1
        $x_1_2 = "Activated" ascii //weight: 1
        $x_1_3 = "root\\CIMV2" ascii //weight: 1
        $x_1_4 = "orphan package" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147743020_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MSR"
        threat_id = "2147743020"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ACKNOWLEDGE -BRK-" ascii //weight: 1
        $x_1_2 = "Generate" ascii //weight: 1
        $x_1_3 = "norwich.net" ascii //weight: 1
        $x_1_4 = "Keygen" ascii //weight: 1
        $x_1_5 = "BKT/BRD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147751727_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MTB"
        threat_id = "2147751727"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keygen" ascii //weight: 1
        $x_1_2 = "keyshot" ascii //weight: 1
        $x_1_3 = "KeyMeshing" ascii //weight: 1
        $x_1_4 = "Luxion Keyshot" ascii //weight: 1
        $x_1_5 = "random number generator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147751727_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MTB"
        threat_id = "2147751727"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bundle" ascii //weight: 1
        $x_1_2 = "Keygen" ascii //weight: 1
        $x_1_3 = "KeygenLayer" ascii //weight: 1
        $x_1_4 = "Press generate" ascii //weight: 1
        $x_1_5 = "CCleaner" ascii //weight: 1
        $x_1_6 = "Piriform MultiGen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147751727_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MTB"
        threat_id = "2147751727"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X-FORCE" ascii //weight: 1
        $x_1_2 = "RIPPGrazey / PHF" ascii //weight: 1
        $x_1_3 = "CONVGrazey / PHF" ascii //weight: 1
        $x_1_4 = "press Generate" ascii //weight: 1
        $x_1_5 = "JamCrackerPro" ascii //weight: 1
        $x_1_6 = "live Keymaker" ascii //weight: 1
        $x_1_7 = "Successfully patched!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147751727_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MTB"
        threat_id = "2147751727"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Generate" ascii //weight: 1
        $x_1_2 = "keygenned by ice/BRD" ascii //weight: 1
        $x_1_3 = "- Keygen by BRD" ascii //weight: 1
        $x_1_4 = "black riders" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147751727_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!MTB"
        threat_id = "2147751727"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TEAM FFF" ascii //weight: 1
        $x_1_2 = "rarreg.key" ascii //weight: 1
        $x_1_3 = "keygen" ascii //weight: 1
        $x_1_4 = "BUTTONBOXWINDOW" ascii //weight: 1
        $x_1_5 = "kentpw@norwich.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Win32_Keygen_R_2147755645_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.R!MTB"
        threat_id = "2147755645"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keygen.exe" ascii //weight: 1
        $x_1_2 = "eygen.exe" ascii //weight: 1
        $x_1_3 = "R2RS1KG2.dll" ascii //weight: 1
        $x_1_4 = "BASSMOD.dll" ascii //weight: 1
        $x_1_5 = "bgm.xm" ascii //weight: 1
        $x_1_6 = "StudioOne KeyGen" ascii //weight: 1
        $x_1_7 = "hsp3debug.dll" ascii //weight: 1
        $x_1_8 = "Ableton 10 KeyGen" ascii //weight: 1
        $x_1_9 = "Traktor Pro 3 KeyGen" ascii //weight: 1
        $x_1_10 = "Native Instruments KeyGen" ascii //weight: 1
        $x_1_11 = "GenerateLicense" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win32_Keygen_P_2147799585_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.P"
        threat_id = "2147799585"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 0c a2 40 00 8d 7d 80 f3 a5 8d 45 b4 50 ff 75 08 a4}  //weight: 1, accuracy: High
        $x_1_2 = "\\nero8x\\Release\\keygen.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_K_2147809819_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.K"
        threat_id = "2147809819"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ghidorah@musician.org" ascii //weight: 2
        $x_2_2 = "keygen" ascii //weight: 2
        $x_2_3 = "http://www.cobans.net" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_D_2147809902_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.D!MTB"
        threat_id = "2147809902"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Generate" ascii //weight: 1
        $x_1_2 = "-|| Keygen by AXiS^FiGHTiNG FOR FUN" ascii //weight: 1
        $x_1_3 = "for dreamhack01" ascii //weight: 1
        $x_1_4 = "GetStartupInfoA" ascii //weight: 1
        $x_1_5 = "GetCPInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_DM_2147814645_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.DM!MTB"
        threat_id = "2147814645"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HSKeygen" ascii //weight: 1
        $x_1_2 = "High-Society Keygen" ascii //weight: 1
        $x_1_3 = "%Mes'agPBoxA" ascii //weight: 1
        $x_1_4 = "um on7imm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_RS_2147899316_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.RS!MTB"
        threat_id = "2147899316"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Universal Keymaker" ascii //weight: 1
        $x_1_2 = "keygen.dll" ascii //weight: 1
        $x_1_3 = "activate.adobe.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_2147903338_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen.MTB"
        threat_id = "2147903338"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keygen.exe" ascii //weight: 1
        $x_1_2 = "ContainsKey" ascii //weight: 1
        $x_1_3 = "Keymaker" ascii //weight: 1
        $x_1_4 = "HelpKeywordAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Keygen_AMTB_2147931343_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!AMTB"
        threat_id = "2147931343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Keygenned by" ascii //weight: 2
        $x_2_2 = "FFFKEYGEN" ascii //weight: 2
        $x_1_3 = "FiGHTiNG FOR FUN PRESENTS" ascii //weight: 1
        $x_1_4 = "SeVeN / FFF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Keygen_AMTB_2147931343_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!AMTB"
        threat_id = "2147931343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "*Keymaker* by Team Cafe" ascii //weight: 2
        $x_2_2 = "Keymaker by Team Cafe" ascii //weight: 2
        $x_1_3 = "Hit the generate button" ascii //weight: 1
        $x_1_4 = "Generate" ascii //weight: 1
        $x_1_5 = "Serial:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Keygen_AMTB_2147931343_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Keygen!AMTB"
        threat_id = "2147931343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keygen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20 6e 2d 67 65 6e 23 30 31 [0-15] 46 61 73 74 54 72 61 63 6b 65 72 20 76 32 2e 30 30}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 61 63 6b 65 72 20 3a 20 4e 2d 47 65 6e [0-4] 50 72 6f 74 65 63 74 69 6f 6e 20 3a 20 43 72 61 70 70 79 20 56 42 20 21 21 21 [0-4] 54 68 6b 73 20 3a 20 4e 2d 47 65 6e 20 63 72 65 77 20 3b 29 [0-4] 4d 41 59 20 54 48 45 20 4c 55 4d 49 4e 4f 55 20 42 45 20 57 49 54 48 20 59 4f 55 20 21 21 [0-150] 45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {56 65 72 73 69 6f 6e 20 4d 6f 6e 6f 70 6f 73 74 65 [0-5] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-10] 50 6f 73 74 65 73 [0-5] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-10] 50 6f 73 74 65 73 [0-5] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-10] 50 6f 73 74 65 73}  //weight: 1, accuracy: Low
        $x_1_4 = "-------www.cerror.tk--" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

