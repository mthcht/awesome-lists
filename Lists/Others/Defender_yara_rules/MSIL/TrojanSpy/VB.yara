rule TrojanSpy_MSIL_VB_A_2147632024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.A"
        threat_id = "2147632024"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Advanced Keylogger" wide //weight: 1
        $x_1_2 = "<ScrollLock Off>" wide //weight: 1
        $x_1_3 = "The Wireshark Network Analyzer" wide //weight: 1
        $x_2_4 = "Logfiles from EasyLogger" wide //weight: 2
        $x_1_5 = "KeyboardHookDelegate" ascii //weight: 1
        $x_2_6 = "antiSandboxie" ascii //weight: 2
        $x_2_7 = "\\Kreylogger Source\\gmail Keylogger\\My Keylogger\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_VB_D_2147636780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.D"
        threat_id = "2147636780"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger reports from: " wide //weight: 1
        $x_2_2 = "KeyStub\\KeyStub\\obj\\Debug\\KeyStub.pdb" ascii //weight: 2
        $x_1_3 = "KeyStub.exe" ascii //weight: 1
        $x_2_4 = "\\waudio32.xml" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_VB_E_2147636786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.E"
        threat_id = "2147636786"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FTP Name:" wide //weight: 1
        $x_2_2 = "Screen_Stealer.Resources" ascii //weight: 2
        $x_1_3 = "\\Start Menu\\Programs\\startup\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_VB_F_2147640331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.F"
        threat_id = "2147640331"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "@Injection@" wide //weight: 4
        $x_4_2 = "AntiKeyscrambler" ascii //weight: 4
        $x_3_3 = "KBDLLHOOKSTRUCT" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_VB_G_2147640728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.G"
        threat_id = "2147640728"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[alt gr]" wide //weight: 2
        $x_2_2 = "[/control]" wide //weight: 2
        $x_3_3 = "KBDLLHOOKSTRUCT" ascii //weight: 3
        $x_2_4 = "virtualKey" ascii //weight: 2
        $x_1_5 = "KeyboardHookDelegate" ascii //weight: 1
        $x_2_6 = "K_Numpad3" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_VB_L_2147643618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.L"
        threat_id = "2147643618"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ftp_upload_NewxFuck" ascii //weight: 4
        $x_4_2 = "Fpt_Fuck_AllInOne_Upload" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_VB_M_2147644042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.M"
        threat_id = "2147644042"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AntiKeyscrambler" ascii //weight: 4
        $x_4_2 = "AntiMalwarebytes" ascii //weight: 4
        $x_2_3 = "MailAddressCollection" ascii //weight: 2
        $x_2_4 = "GetExecutingAssembly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_VB_O_2147647146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.O"
        threat_id = "2147647146"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "(Password Encrypted With Sha1 Encrtyption Algorithm_Find On Google For Sha1 Decryption)" wide //weight: 5
        $x_5_2 = "Rapzo Logger v 2.0   Stealer Logs From -" wide //weight: 5
        $x_5_3 = "Rapzo Logger - Private Edition Ftp Logs On" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_VB_Q_2147651548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/VB.Q"
        threat_id = "2147651548"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Backspace]" wide //weight: 1
        $x_1_2 = "\\logging.txt" wide //weight: 1
        $x_1_3 = "KBDLLHOOKSTRUCT" ascii //weight: 1
        $x_2_4 = "ftp://mike:U3CruzerMicro@nsc.mine.nu/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

