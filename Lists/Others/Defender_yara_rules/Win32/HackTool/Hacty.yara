rule HackTool_Win32_Hacty_A_2147602259_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Hacty.gen!A"
        threat_id = "2147602259"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hacty"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 6f 61 64 65 72 3e 20 48 6f 6f 6b 20 73 68 6f 75 6c 64 20 62 65 20 73 65 74 20 6e 6f 77 [0-16] 4c 6f 61 64 65 72 3e 20 43 61 6c 6c 69 6e 67 20 6c 6f 61 64 20 66 75 6e 63 74 69 6f 6e [0-16] 4c 6f 61 64 65 72 3e 20 46 41 49 4c 45 44}  //weight: 10, accuracy: Low
        $x_10_2 = {53 65 74 55 70 48 6f 6f 6b [0-5] 4c 6f 61 64 65 72 3e 20 52 65 73 6f 6c 76 69 6e 67 20 6c 6f 61 64 20 66 75 6e 63 74 69 6f 6e [0-16] 4e 74 49 6c 6c 75 73 69 6f 6e [0-2] 64 6c 6c [0-2] 4c 6f 61 64 65 72 3e 20 6c 6f 61 64 69 6e 67 20 4e 54 49 6c 6c 75 73 69 6f 6e}  //weight: 10, accuracy: Low
        $x_5_3 = "NTIllusion.dll" wide //weight: 5
        $x_3_4 = "Vanquish - DLL injection failed:" ascii //weight: 3
        $x_3_5 = "Prepare injector failed! Cannot find address of LoadLibraryW" ascii //weight: 3
        $x_3_6 = "Unhandled exception caught! Please forward this information to the author" ascii //weight: 3
        $x_1_7 = "***Application: %s" ascii //weight: 1
        $x_1_8 = "***Time: %s" ascii //weight: 1
        $x_1_9 = "***Date: %s" ascii //weight: 1
        $x_5_10 = "Vanquish Autoloader v0.1 beta10" ascii //weight: 5
        $x_3_11 = "Cannot open SCM! Maybe not admin!?" ascii //weight: 3
        $x_3_12 = "Cannot open Vanquish Service! Maybe not installed!?" ascii //weight: 3
        $x_3_13 = "VanquishAutoInjectingDLL" wide //weight: 3
        $x_2_14 = "Failed to inject VANQUISH!" ascii //weight: 2
        $x_2_15 = "Lucky! Lucky! By retrying I managed to avoid overflowing the Indexor" ascii //weight: 2
        $x_2_16 = "Gee! Overflowed the Indexor! Hidden registry values may show up" ascii //weight: 2
        $x_2_17 = "Oops! Overflowed dwIndexKEY! Some keys will not show up" ascii //weight: 2
        $x_2_18 = "Oops! Overflowed dwIndexVAL! Some values will not show up" ascii //weight: 2
        $x_2_19 = "Finally somebody invoked RegQueryMultipleValuesW" ascii //weight: 2
        $x_2_20 = "Finally somebody invoked RegQueryMultipleValuesA" ascii //weight: 2
        $x_2_21 = "Error allocating %u bytes in EnumServiceStatusA" ascii //weight: 2
        $x_2_22 = "Not able to EnumServicesA properly (need additional %u bytes)" ascii //weight: 2
        $x_2_23 = "Error allocating %u bytes in EnumServiceStatusW" ascii //weight: 2
        $x_2_24 = "Not able to EnumServicesW properly (need additional %u bytes)" ascii //weight: 2
        $x_2_25 = "You cannot modify system time! Instead, your attempt has been logged :)" ascii //weight: 2
        $x_2_26 = "You cannot delete protected files/folders! Instead, your attempt has been logged :)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((10 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_3_*) and 2 of ($x_1_*))) or
            ((6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Hacty_B_2147602260_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Hacty.gen!B"
        threat_id = "2147602260"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hacty"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MZ S C O R EPE" ascii //weight: 2
        $x_3_2 = "** Running kInject v1.0 by Kdm (kodmaker@netcourrier.com) **" ascii //weight: 3
        $x_3_3 = "t open process. (Sure it exists ?)" ascii //weight: 3
        $x_2_4 = "GetPidByName failed" ascii //weight: 2
        $x_2_5 = "OpenProcess failed, triggering DebugPrivilege" ascii //weight: 2
        $x_3_6 = "[!] Error while getting LoadLibraryA address" ascii //weight: 3
        $x_2_7 = "[!] Cannot create thread" ascii //weight: 2
        $x_2_8 = "[!] Thread TIME OUT" ascii //weight: 2
        $x_3_9 = "ect.exe [process path/Pid] [dll path] [--create / --runtime] [--resolve] [--force]" ascii //weight: 3
        $x_2_10 = "--create     : program will create the process before injecting" ascii //weight: 2
        $x_2_11 = "--runtime    : inject already existing process" ascii //weight: 2
        $x_2_12 = "--resolve    : get process id from executable name" ascii //weight: 2
        $x_2_13 = "--force      : load SeDebugPrivilege to break into target process" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

