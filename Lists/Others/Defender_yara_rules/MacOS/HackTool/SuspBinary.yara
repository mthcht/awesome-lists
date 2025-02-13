rule HackTool_MacOS_SuspBinary_V_2147908412_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspBinary.V"
        threat_id = "2147908412"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspBinary"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CYM_PipeFile_" ascii //weight: 1
        $x_1_2 = "Cymulate@TMR" ascii //weight: 1
        $x_1_3 = "CymulateDylibHijack" ascii //weight: 1
        $x_1_4 = "<CymArgs>" ascii //weight: 1
        $x_1_5 = "CymulateEDRScenarioExecutor" ascii //weight: 1
        $x_1_6 = "Cymulate/Agent/edr/" ascii //weight: 1
        $x_1_7 = "CYMULATE_EDR_MUTEX" ascii //weight: 1
        $x_1_8 = "edr_attacks_path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_MacOS_SuspBinary_A_2147908478_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspBinary.A"
        threat_id = "2147908478"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspBinary"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "malicious_dylib" ascii //weight: 1
        $x_1_2 = "com.apple.TCC/TCC.db" ascii //weight: 1
        $x_1_3 = "otool -l %s | grep LC_LOAD_WEAK_DYLIB" ascii //weight: 1
        $x_1_4 = "CymulateEDRScenarioExecutor" ascii //weight: 1
        $x_1_5 = "com.apple.security.cs.disable-library-validation" ascii //weight: 1
        $x_1_6 = "edr_attacks_path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_MacOS_SuspBinary_B_2147908479_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspBinary.B"
        threat_id = "2147908479"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspBinary"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.apple.TCC/TCC.db \"select * from access where service='kTCCServiceSystemPolicyAllFiles'" ascii //weight: 1
        $x_1_2 = "crontab -l | echo \"%s\" | crontab -" ascii //weight: 1
        $x_1_3 = "CymulateEDRScenarioExecutor" ascii //weight: 1
        $x_1_4 = "edr_attacks_path" ascii //weight: 1
        $x_1_5 = "su root -c" ascii //weight: 1
        $x_1_6 = "CYMULATE_EDR_MUTEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_MacOS_SuspBinary_X_2147908626_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspBinary.X"
        threat_id = "2147908626"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspBinary"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CymulateReverseShell" ascii //weight: 1
        $x_1_2 = "CymulateCoinMinerCore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspBinary_P_2147908640_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspBinary.P"
        threat_id = "2147908640"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspBinary"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CymulateReverseShell.dll" ascii //weight: 5
        $x_5_2 = "CymulateCoinMinerCore.dll" ascii //weight: 5
        $x_1_3 = "CRYPTO_add_lock_ptr" ascii //weight: 1
        $x_1_4 = "is_exe_enabled_for_execution" ascii //weight: 1
        $x_1_5 = "Caller is Reverse P/Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

