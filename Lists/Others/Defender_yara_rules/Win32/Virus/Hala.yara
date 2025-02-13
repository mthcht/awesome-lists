rule Virus_Win32_Hala_C_2147602587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hala.C"
        threat_id = "2147602587"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hala"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "?action=post&HD=%s&HN=%s&OT=%d&IV=%s&MM=%d" ascii //weight: 3
        $x_2_2 = "__DL5XYEX__" ascii //weight: 2
        $x_3_3 = "__DL_CORE5_MUTEX__" ascii //weight: 3
        $x_4_4 = "nbt-dragonraja2006.exe" ascii //weight: 4
        $x_4_5 = "\\d3d8xof.dll" ascii //weight: 4
        $x_4_6 = "dragonraja.exe" ascii //weight: 4
        $x_4_7 = "d9dx.dll" ascii //weight: 4
        $x_4_8 = "zhengtu.exe" ascii //weight: 4
        $x_4_9 = "\\d9dx.dll" ascii //weight: 4
        $x_4_10 = "trojankiller.exe" ascii //weight: 4
        $x_4_11 = "kartrider.exe" ascii //weight: 4
        $x_1_12 = "sealspeed.exe" ascii //weight: 1
        $x_1_13 = "xy2.exe" ascii //weight: 1
        $x_1_14 = "nmservice.exe" ascii //weight: 1
        $x_1_15 = "asktao.exe" ascii //weight: 1
        $x_1_16 = "audition.exe" ascii //weight: 1
        $x_1_17 = "patcher.exe" ascii //weight: 1
        $x_1_18 = "flyff.exe" ascii //weight: 1
        $x_1_19 = "dbfsupdate.exe" ascii //weight: 1
        $x_1_20 = "mhclient-connect.exe" ascii //weight: 1
        $x_1_21 = "zuonline.exe" ascii //weight: 1
        $x_1_22 = "neuz.exe" ascii //weight: 1
        $x_1_23 = "ztconfig.exe" ascii //weight: 1
        $x_1_24 = "maplestory.exe" ascii //weight: 1
        $x_1_25 = "config.exe" ascii //weight: 1
        $x_1_26 = "hs.exe" ascii //weight: 1
        $x_1_27 = "mjonline.exe" ascii //weight: 1
        $x_1_28 = "au_unins_web.exe" ascii //weight: 1
        $x_1_29 = "patchupdate.exe" ascii //weight: 1
        $x_1_30 = "cabalmain9x.exe" ascii //weight: 1
        $x_1_31 = "gc.exe" ascii //weight: 1
        $x_1_32 = "main.exe" ascii //weight: 1
        $x_1_33 = "sfc.dll" ascii //weight: 1
        $x_1_34 = "nsstarter.exe" ascii //weight: 1
        $x_1_35 = "wooolcfg.exe" ascii //weight: 1
        $x_1_36 = "mts.exe" ascii //weight: 1
        $x_1_37 = "userpic.exe" ascii //weight: 1
        $x_1_38 = "cabal.exe" ascii //weight: 1
        $x_1_39 = "nmcosrv.exe" ascii //weight: 1
        $x_1_40 = "xlqy2.exe" ascii //weight: 1
        $x_1_41 = "woool.exe" ascii //weight: 1
        $x_1_42 = "meteor.exe" ascii //weight: 1
        $x_1_43 = "xy2player.exe" ascii //weight: 1
        $x_1_44 = "autoupdate.exe" ascii //weight: 1
        $x_1_45 = "SHDOCVW.DLL" ascii //weight: 1
        $x_1_46 = "zfs.exe" ascii //weight: 1
        $x_1_47 = "dk2.exe" ascii //weight: 1
        $x_1_48 = "game.exe" ascii //weight: 1
        $x_1_49 = "cabalmain.exe" ascii //weight: 1
        $x_1_50 = "ca.exe" ascii //weight: 1
        $x_1_51 = "wb-service.exe" ascii //weight: 1
        $x_1_52 = "%s*.*" ascii //weight: 1
        $x_1_53 = ":\\WINNT\\" ascii //weight: 1
        $x_2_54 = "ACPI#PNPDODO#1#Amd_DL5" ascii //weight: 2
        $x_1_55 = "difftime" ascii //weight: 1
        $x_2_56 = "Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 2
        $x_1_57 = "CreateRemoteThread" ascii //weight: 1
        $x_1_58 = "%d.%d" ascii //weight: 1
        $x_1_59 = "GetThreadContext" ascii //weight: 1
        $x_1_60 = "CheckBKFlags" ascii //weight: 1
        $x_2_61 = "GlobalMemoryStatus" ascii //weight: 2
        $x_1_62 = "WININET" ascii //weight: 1
        $x_1_63 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_64 = "explorer.exe" ascii //weight: 1
        $x_2_65 = "GetLogicalDrives" ascii //weight: 2
        $x_1_66 = "SfcIsFileProtected" ascii //weight: 1
        $x_2_67 = "LOCAL SETTINGS\\TEMP\\" ascii //weight: 2
        $x_2_68 = "htmlfile\\shell\\open\\command" ascii //weight: 2
        $x_1_69 = "DirectX DLL" ascii //weight: 1
        $x_2_70 = "Software\\Intel" ascii //weight: 2
        $x_2_71 = "Software\\Google" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_2_*) and 52 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*) and 51 of ($x_1_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*) and 49 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 52 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*) and 50 of ($x_1_*))) or
            ((2 of ($x_3_*) and 8 of ($x_2_*) and 48 of ($x_1_*))) or
            ((2 of ($x_3_*) and 9 of ($x_2_*) and 46 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_2_*) and 52 of ($x_1_*))) or
            ((1 of ($x_4_*) and 8 of ($x_2_*) and 50 of ($x_1_*))) or
            ((1 of ($x_4_*) and 9 of ($x_2_*) and 48 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 51 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 49 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 47 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 45 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 52 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 50 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 48 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 46 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 44 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 42 of ($x_1_*))) or
            ((2 of ($x_4_*) and 5 of ($x_2_*) and 52 of ($x_1_*))) or
            ((2 of ($x_4_*) and 6 of ($x_2_*) and 50 of ($x_1_*))) or
            ((2 of ($x_4_*) and 7 of ($x_2_*) and 48 of ($x_1_*))) or
            ((2 of ($x_4_*) and 8 of ($x_2_*) and 46 of ($x_1_*))) or
            ((2 of ($x_4_*) and 9 of ($x_2_*) and 44 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 51 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 49 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 47 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 45 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 43 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 41 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 52 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 50 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 48 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 46 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 44 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 42 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 40 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 38 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_2_*) and 52 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_2_*) and 50 of ($x_1_*))) or
            ((3 of ($x_4_*) and 5 of ($x_2_*) and 48 of ($x_1_*))) or
            ((3 of ($x_4_*) and 6 of ($x_2_*) and 46 of ($x_1_*))) or
            ((3 of ($x_4_*) and 7 of ($x_2_*) and 44 of ($x_1_*))) or
            ((3 of ($x_4_*) and 8 of ($x_2_*) and 42 of ($x_1_*))) or
            ((3 of ($x_4_*) and 9 of ($x_2_*) and 40 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 51 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 49 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 47 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 45 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 43 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 41 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 39 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 37 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 52 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 50 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 48 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 46 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 44 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 42 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 40 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 38 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 36 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 34 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_2_*) and 52 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_2_*) and 50 of ($x_1_*))) or
            ((4 of ($x_4_*) and 3 of ($x_2_*) and 48 of ($x_1_*))) or
            ((4 of ($x_4_*) and 4 of ($x_2_*) and 46 of ($x_1_*))) or
            ((4 of ($x_4_*) and 5 of ($x_2_*) and 44 of ($x_1_*))) or
            ((4 of ($x_4_*) and 6 of ($x_2_*) and 42 of ($x_1_*))) or
            ((4 of ($x_4_*) and 7 of ($x_2_*) and 40 of ($x_1_*))) or
            ((4 of ($x_4_*) and 8 of ($x_2_*) and 38 of ($x_1_*))) or
            ((4 of ($x_4_*) and 9 of ($x_2_*) and 36 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 51 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 49 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 47 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 45 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 43 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 41 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 39 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 37 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 35 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 33 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 48 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 46 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 44 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 42 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 40 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 38 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 36 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 34 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 32 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 30 of ($x_1_*))) or
            ((5 of ($x_4_*) and 50 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*) and 48 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_2_*) and 46 of ($x_1_*))) or
            ((5 of ($x_4_*) and 3 of ($x_2_*) and 44 of ($x_1_*))) or
            ((5 of ($x_4_*) and 4 of ($x_2_*) and 42 of ($x_1_*))) or
            ((5 of ($x_4_*) and 5 of ($x_2_*) and 40 of ($x_1_*))) or
            ((5 of ($x_4_*) and 6 of ($x_2_*) and 38 of ($x_1_*))) or
            ((5 of ($x_4_*) and 7 of ($x_2_*) and 36 of ($x_1_*))) or
            ((5 of ($x_4_*) and 8 of ($x_2_*) and 34 of ($x_1_*))) or
            ((5 of ($x_4_*) and 9 of ($x_2_*) and 32 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 47 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 45 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 43 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 41 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 39 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 37 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 35 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 33 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 31 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 29 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 44 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 42 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 40 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 38 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 36 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 34 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 32 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 30 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 28 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 26 of ($x_1_*))) or
            ((6 of ($x_4_*) and 46 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_2_*) and 44 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_2_*) and 42 of ($x_1_*))) or
            ((6 of ($x_4_*) and 3 of ($x_2_*) and 40 of ($x_1_*))) or
            ((6 of ($x_4_*) and 4 of ($x_2_*) and 38 of ($x_1_*))) or
            ((6 of ($x_4_*) and 5 of ($x_2_*) and 36 of ($x_1_*))) or
            ((6 of ($x_4_*) and 6 of ($x_2_*) and 34 of ($x_1_*))) or
            ((6 of ($x_4_*) and 7 of ($x_2_*) and 32 of ($x_1_*))) or
            ((6 of ($x_4_*) and 8 of ($x_2_*) and 30 of ($x_1_*))) or
            ((6 of ($x_4_*) and 9 of ($x_2_*) and 28 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 43 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 41 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 39 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 37 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 35 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 33 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 31 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 29 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 27 of ($x_1_*))) or
            ((6 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 25 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 40 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 38 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 36 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 34 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 32 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 30 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 28 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 26 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 24 of ($x_1_*))) or
            ((6 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 22 of ($x_1_*))) or
            ((7 of ($x_4_*) and 42 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_2_*) and 40 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_2_*) and 38 of ($x_1_*))) or
            ((7 of ($x_4_*) and 3 of ($x_2_*) and 36 of ($x_1_*))) or
            ((7 of ($x_4_*) and 4 of ($x_2_*) and 34 of ($x_1_*))) or
            ((7 of ($x_4_*) and 5 of ($x_2_*) and 32 of ($x_1_*))) or
            ((7 of ($x_4_*) and 6 of ($x_2_*) and 30 of ($x_1_*))) or
            ((7 of ($x_4_*) and 7 of ($x_2_*) and 28 of ($x_1_*))) or
            ((7 of ($x_4_*) and 8 of ($x_2_*) and 26 of ($x_1_*))) or
            ((7 of ($x_4_*) and 9 of ($x_2_*) and 24 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 39 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 37 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 35 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 33 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 31 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 29 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 27 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 25 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 23 of ($x_1_*))) or
            ((7 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 21 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 36 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 34 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 32 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 30 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 28 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 26 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 24 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 22 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 20 of ($x_1_*))) or
            ((7 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 18 of ($x_1_*))) or
            ((8 of ($x_4_*) and 38 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_2_*) and 36 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_2_*) and 34 of ($x_1_*))) or
            ((8 of ($x_4_*) and 3 of ($x_2_*) and 32 of ($x_1_*))) or
            ((8 of ($x_4_*) and 4 of ($x_2_*) and 30 of ($x_1_*))) or
            ((8 of ($x_4_*) and 5 of ($x_2_*) and 28 of ($x_1_*))) or
            ((8 of ($x_4_*) and 6 of ($x_2_*) and 26 of ($x_1_*))) or
            ((8 of ($x_4_*) and 7 of ($x_2_*) and 24 of ($x_1_*))) or
            ((8 of ($x_4_*) and 8 of ($x_2_*) and 22 of ($x_1_*))) or
            ((8 of ($x_4_*) and 9 of ($x_2_*) and 20 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 35 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 33 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 31 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 29 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 27 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 25 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 23 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 21 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 19 of ($x_1_*))) or
            ((8 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 17 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 32 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 30 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 28 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 26 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 24 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 22 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 20 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 18 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((8 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 14 of ($x_1_*))) or
            (all of ($x*))
        )
}

