rule Trojan_MSIL_Spy_Keylogger_2147779585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.Keylogger.OQ!MTB"
        threat_id = "2147779585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "OQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 1f 43 fe 01 5f 2c 19 7e ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 80 ?? ?? ?? 04 38 fc 35 00 00 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 1f 56 fe 01 5f 2c 19 7e ?? ?? ?? 04 72 ?? ?? ?? 70}  //weight: 10, accuracy: Low
        $x_5_2 = "Grieve Logger Public V2 - Logs:" ascii //weight: 5
        $x_5_3 = "+====Logs====+" ascii //weight: 5
        $x_4_4 = "DisableTaskMgr" ascii //weight: 4
        $x_4_5 = {5c 54 6d 70 ?? ?? ?? ?? 2e 65 78 65}  //weight: 4, accuracy: Low
        $x_3_6 = "get_Keyboard" ascii //weight: 3
        $x_3_7 = "get_CapsLock" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Spy_Keylogger_2147779590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.Keylogger.ADK!MTB"
        threat_id = "2147779590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "ADK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mykeylogger" ascii //weight: 5
        $x_5_2 = "LowLevelKeyboardProc" ascii //weight: 5
        $x_5_3 = "C:\\ProgramData\\mylog_archive.txt" ascii //weight: 5
        $x_4_4 = "CallNextHookEx" ascii //weight: 4
        $x_4_5 = "HookCallback" ascii //weight: 4
        $x_4_6 = "mylog.txt" ascii //weight: 4
        $x_3_7 = "MAX_KEYSTROKES" ascii //weight: 3
        $x_3_8 = "malware.attack" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Spy_Keylogger_2147780657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.Keylogger.EDN!MTB"
        threat_id = "2147780657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "EDN: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "HookCallback" ascii //weight: 5
        $x_5_2 = "CallNextHookEx" ascii //weight: 5
        $x_4_3 = "\\log.txt" ascii //weight: 4
        $x_4_4 = "LowLevelKeyboardProc" ascii //weight: 4
        $x_4_5 = "WH_KEYBOARD_LL" ascii //weight: 4
        $x_4_6 = "WM_KEYDOWN" ascii //weight: 4
        $x_4_7 = "UnhookWindowsHookEx" ascii //weight: 4
        $x_3_8 = "StreamWriter" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_Keylogger_2147781331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.Keylogger.DGY!MTB"
        threat_id = "2147781331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "DGY: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "HookProc" ascii //weight: 5
        $x_4_2 = "WH_JOURNALRECORD" ascii //weight: 4
        $x_4_3 = "WH_JOURNALPLAYBACK" ascii //weight: 4
        $x_4_4 = "WH_KEYBOARD_LL" ascii //weight: 4
        $x_3_5 = "LLKHF_INJECTED" ascii //weight: 3
        $x_3_6 = "GetAsyncKeyState" ascii //weight: 3
        $x_3_7 = "TextLogger" ascii //weight: 3
        $x_3_8 = "GetWindowText" ascii //weight: 3
        $x_3_9 = "GetCurrentProcess" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_Bulz_2147781757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.Bulz.AH!MTB"
        threat_id = "2147781757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "AH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 25 33 00 16 ?? ?? 01 ?? ?? ?? 1c ?? ?? ?? 07 ?? ?? ?? 05 ?? ?? ?? 11 ?? ?? ?? 03 ?? ?? ?? 29 ?? ?? ?? 2a ?? ?? ?? 0c ?? ?? ?? 02 ?? ?? ?? 05 ?? ?? ?? 05}  //weight: 10, accuracy: Low
        $x_3_2 = "GetEnvironmentVariable" ascii //weight: 3
        $x_3_3 = "\\cmd.bat" ascii //weight: 3
        $x_3_4 = "WriteAllText" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_LiveSnoop_2147781935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.LiveSnoop.AH!MTB"
        threat_id = "2147781935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "AH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LiveSnoop_Agent" ascii //weight: 3
        $x_3_2 = "DebuggerHiddenAttribute" ascii //weight: 3
        $x_3_3 = "set_ShutdownStyle" ascii //weight: 3
        $x_3_4 = "set_ShowInTaskbar" ascii //weight: 3
        $x_3_5 = "DownloadFile" ascii //weight: 3
        $x_3_6 = "ToBase64String" ascii //weight: 3
        $x_3_7 = "HttpWebRequest" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_DJN_2147785246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.DJN!MTB"
        threat_id = "2147785246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AllWalletsRule" ascii //weight: 1
        $x_1_2 = "CoinomiRule" ascii //weight: 1
        $x_1_3 = "JaxxRule" ascii //weight: 1
        $x_1_4 = "ArmoryRule" ascii //weight: 1
        $x_1_5 = "ProtonVPNRule" ascii //weight: 1
        $x_1_6 = "ExodusRule" ascii //weight: 1
        $x_1_7 = "ElectrumRule" ascii //weight: 1
        $x_1_8 = "GuardaRule" ascii //weight: 1
        $x_1_9 = "AtomicRule" ascii //weight: 1
        $x_1_10 = "ScannedBrowser" ascii //weight: 1
        $x_1_11 = "ScannedCookie" ascii //weight: 1
        $x_1_12 = "get_ScanWallets" ascii //weight: 1
        $x_1_13 = "ScanDiscord" ascii //weight: 1
        $x_1_14 = "ScanVPN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_CYF_2147786250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.CYF!MTB"
        threat_id = "2147786250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Built.exe" ascii //weight: 1
        $x_1_2 = "Ducky=)" ascii //weight: 1
        $x_1_3 = "C1255198513" ascii //weight: 1
        $x_1_4 = "C3554254475" ascii //weight: 1
        $x_1_5 = "C3904355907" ascii //weight: 1
        $x_1_6 = {fe 0e 06 00 fe 0d 06 00 28 ec 01 00 0a fe 0e 04 00 fe 0c 03 00 20 05 00 00 00 20 40 00 00 00 fe 0d 05 00 28 ?? 04 00 06 26 28 43 00 00 0a 20 04 00 00 00 fe 01 fe 0e 07 00 fe 0c 07 00 39 57 00 00 00 00 fe 0c 03 00 20 00 00 00 00 20 e9 00 00 00 28 ed 01 00 0a 00 fe 0c 03 00 20 01 00 00 00 fe 0d 04 00 28 ee 01 00 0a fe 0d 03 00 28 ee 01 00 0a 59 20 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_Noon_2147788952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.Noon.AL!MTB"
        threat_id = "2147788952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "AL: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 02 6f 53 00 00 0a 00 02 18 5d 16 fe 01 0c 08 2c 17 02 6c 23 00 00 00 00 00 00 00 40 5b 28 55 00 00 0a b7 10 00 00 2b 09 00 19 02 d8 17 d6 10 00 00 00 02 17 fe 01 16 fe 01 0d 09 2d c2 07 02 6f 53 00 00 0a 00 07 0a 2b 00 06 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_SCC_2147798240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.SCC!MTB"
        threat_id = "2147798240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$689e6b2b-5c39-4822-a4be-bb7ffd652e77" ascii //weight: 10
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetTypeFromHandle" ascii //weight: 1
        $x_1_4 = "CurrentDomain_AssemblyResolve" ascii //weight: 1
        $x_1_5 = "Newtonsoft" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_ABDSA_2147805127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.ABDSA!MTB"
        threat_id = "2147805127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$939b6d4f-6a2f-43ef-82f6-56e424585645" ascii //weight: 10
        $x_1_2 = "ICore" ascii //weight: 1
        $x_1_3 = "ParallelLoopResult" ascii //weight: 1
        $x_1_4 = "Dispose" ascii //weight: 1
        $x_1_5 = "Disposition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_FRM_2147809849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.FRM!MTB"
        threat_id = "2147809849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 15 00 00 0a 0a 00 06 1f 10 8d 1f 00 00 01 25 d0 06 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 1f 10 8d 1f 00 00 01 25 d0 05 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 03 16 03 8e 69 6f ?? ?? ?? 0a 0b de 0b 06 2c 07 06 6f ?? ?? ?? 0a 00 dc 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_MEGA_2147810532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.MEGA!MTB"
        threat_id = "2147810532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 72 01 00 00 70 12 00 73 08 00 00 0a 26 06 2d 01 2a 17 0b 16 0c 16 0d 16 13 04 16 13 05 72 13 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 72 2d 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 3a ca 00 00 00 72 97 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 72 a9 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 1a 28 ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 72 cb 00 00 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 08 11 07 11 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_KAREGA_2147811639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.KAREGA!MTB"
        threat_id = "2147811639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 1e 8d 44 00 00 01 25 d0 9d 00 00 04 28 ?? ?? ?? 0a 0b 73 22 00 00 0a 0c 00 73 23 00 00 0a 0d 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 6b 00 00 70}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_FRSI_2147812171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.FRSI!MTB"
        threat_id = "2147812171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 8d 7d 00 00 01 25 16 1f 60 9d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 17 8d 10 00 00 01 25 16 02 a2 28 ?? ?? ?? 0a 74 39 00 00 01 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_JLNG_2147813722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.JLNG!MTB"
        threat_id = "2147813722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "transfer.sh/get" wide //weight: 2
        $x_2_2 = "Replace" ascii //weight: 2
        $x_2_3 = "FromBase64String" ascii //weight: 2
        $x_2_4 = "InvokeMember" ascii //weight: 2
        $x_2_5 = "NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX" wide //weight: 2
        $x_2_6 = "GetType" ascii //weight: 2
        $x_2_7 = "Skidomoney.Money" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_QYA_2147813724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.QYA!MTB"
        threat_id = "2147813724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 02 26 16 28 ?? ?? ?? 06 0a 06 28 ?? ?? ?? 06 25 26 03 50 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0b 28 ?? ?? ?? 06 25 26 0c 08 07 28 ?? ?? ?? 06 08 28 ?? ?? ?? 06 28 ?? ?? ?? 06 08 28 ?? ?? ?? 06 25 26 02 50 28 ?? ?? ?? 06 25 26 02 50 8e 69 28 ?? ?? ?? 06 25 26 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_XYA_2147813725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.XYA!MTB"
        threat_id = "2147813725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 0b 26 20 cc 01 00 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 25 26 0a 06 28 ?? ?? ?? 06 25 26 03 50 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0b 28 ?? ?? ?? 06 25 26 0c 08 07 28 ?? ?? ?? 06 08 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 08 28 ?? ?? ?? 06 25 26 02 50 28 ?? ?? ?? 06 25 26 02 50 8e 69 28 ?? ?? ?? 06 25 26 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spy_KMS_2147813727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spy.KMS!MTB"
        threat_id = "2147813727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 41 00 00 0a 0b 07 1f 10 8d 38 00 00 01 25 d0 0c 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 1f 10 8d 38 00 00 01 25 d0 0d 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 03 16 03 8e 69 6f ?? ?? ?? 0a 0a de 0c 00 07 2c 07 07 6f ?? ?? ?? 0a 00 dc 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

