rule Trojan_MSIL_KeyLogger_BN_2147811146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.BN!MTB"
        threat_id = "2147811146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsa1997@o2.pl" wide //weight: 1
        $x_1_2 = "testing_kl" wide //weight: 1
        $x_1_3 = "testingkl@yahoo.com" wide //weight: 1
        $x_1_4 = "hook_KeyPressed" ascii //weight: 1
        $x_1_5 = "[F12]" wide //weight: 1
        $x_1_6 = "PASSWORD" ascii //weight: 1
        $x_1_7 = "Form1_Load" ascii //weight: 1
        $x_1_8 = "[CAPSLOCK]" wide //weight: 1
        $x_1_9 = "[R_CTRL]" wide //weight: 1
        $x_1_10 = "[PRINTSCREEN]" wide //weight: 1
        $x_1_11 = "[WIN]" wide //weight: 1
        $x_1_12 = "NetworkCredential" ascii //weight: 1
        $x_1_13 = "keyboardHookProc" ascii //weight: 1
        $x_1_14 = "Append" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SVR_2147835866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SVR!MTB"
        threat_id = "2147835866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 0e 04 11 05 1f 10 5a 7e 0c 00 00 04 20 ff 7f 00 00 03 08 92 58 91 58 a3 21 00 00 02 0e 05 28 ?? ?? ?? 06 00 02 7e 0d 00 00 04 20 ff 7f 00 00 03 08 92 58 a3 21 00 00 02 0e 05 28 ?? ?? ?? 06 00 08 17 58 d2 0c 00 08 11 04 fe 02 16 fe 01 13 0d 11 0d 3a 40 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SSVP_2147837089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SSVP!MTB"
        threat_id = "2147837089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 04 00 00 04 06 9a 6f ?? ?? ?? 06 02 fe 01 0b 07 2c 05 00 17 0c 2b 15 00 06 17 58 0a 06 7e 05 00 00 04 fe 04 0d 09 2d d6}  //weight: 2, accuracy: Low
        $x_1_2 = "muQv.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SPQP_2147837802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SPQP!MTB"
        threat_id = "2147837802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SPAB_2147841023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SPAB!MTB"
        threat_id = "2147841023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 09 07 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 07 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SPAT_2147842176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SPAT!MTB"
        threat_id = "2147842176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 06 9a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 09 72 a1 00 00 70 16 28 ?? ?? ?? 0a 16 33 08 07 06 9a 6f ?? ?? ?? 0a 06 17 d6 0a 06 08 31 d3}  //weight: 3, accuracy: Low
        $x_1_2 = "bejn666Stub" wide //weight: 1
        $x_1_3 = "@DmCD95fdwysEecVxJbRA@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_NKA_2147850780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.NKA!MTB"
        threat_id = "2147850780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 22 00 00 0a 6f ?? 00 00 0a 00 00 28 ?? 00 00 06 0b 07 16 28 ?? 00 00 06 26 06 6f ?? 00 00 06 16 fe 01 0d 09 2c 10 00 06 6f ?? 00 00 06 00 06 6f ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Keystrokes saved from user" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_RDF_2147892291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.RDF!MTB"
        threat_id = "2147892291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bf506a75-cd19-4333-882c-265ca8454c97" ascii //weight: 1
        $x_1_2 = "KeyLogger" ascii //weight: 1
        $x_1_3 = "LowLevelKeyboardProc" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_RDG_2147894304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.RDG!MTB"
        threat_id = "2147894304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "142082ea-3f2c-4679-8a4a-fdb3e4d0af0a" ascii //weight: 1
        $x_1_2 = "WinDef" ascii //weight: 1
        $x_1_3 = "KeyTestJP" ascii //weight: 1
        $x_1_4 = "Tela" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_MMO_2147899150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.MMO!MTB"
        threat_id = "2147899150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 75 0a 00 00 01 02 08 28 ?? 00 00 06 6f ?? 00 00 0a 11 05 74 ?? 00 00 01 6f ?? 00 00 0a 11 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "KeyLogger.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_ARA_2147899260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.ARA!MTB"
        threat_id = "2147899260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "As you reboot, you find that your MBR has been overwritten." ascii //weight: 2
        $x_1_2 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_3 = "SpyTheSpy" ascii //weight: 1
        $x_1_4 = "wireshark" ascii //weight: 1
        $x_1_5 = "Sandboxie Control" ascii //weight: 1
        $x_1_6 = "processhacker" ascii //weight: 1
        $x_1_7 = "dnSpy" ascii //weight: 1
        $x_1_8 = "VBoxService" ascii //weight: 1
        $x_1_9 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_11 = "pastebin.com/raw/???" ascii //weight: 2
        $x_2_12 = "Your system is now mine" ascii //weight: 2
        $x_1_13 = "Select * From AntiVirusProduct" ascii //weight: 1
        $x_1_14 = "cmd /c start shutdown /r /f /t 3" ascii //weight: 1
        $x_1_15 = "cmd /c sc delete windefend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_MVA_2147900920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.MVA!MTB"
        threat_id = "2147900920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Discord Keylogger.pdb" ascii //weight: 2
        $x_1_2 = "HootKeys" ascii //weight: 1
        $x_1_3 = "webhookstart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_KeyLogger_ARAQ_2147908027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.ARAQ!MTB"
        threat_id = "2147908027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Temp\\Logs\\" wide //weight: 2
        $x_2_2 = "Captured Keystrokes" wide //weight: 2
        $x_2_3 = "These are your keylogs files" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_ARAQ_2147908027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.ARAQ!MTB"
        threat_id = "2147908027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "keystrokes.txt" wide //weight: 2
        $x_1_2 = "[ESC]" wide //weight: 1
        $x_1_3 = "[CTRL]" wide //weight: 1
        $x_1_4 = "[Back]" wide //weight: 1
        $x_1_5 = "[WIN]" wide //weight: 1
        $x_1_6 = "[Tab]" wide //weight: 1
        $x_1_7 = "[DEL]" wide //weight: 1
        $x_2_8 = "Keylogger" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_KeyLogger_SMP_2147911851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SMP!MTB"
        threat_id = "2147911851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 06 00 00 04 18 6f ?? ?? ?? 0a 00 7e 06 00 00 04 6f ?? ?? ?? 0a 0a 2b 00 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SPBF_2147915070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SPBF!MTB"
        threat_id = "2147915070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 11 04 39 ea 06 00 00 09 1f 20 33 11 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0a 38 d4 06 00 00 09 1f 0d 33 16}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_NK_2147928809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.NK!MTB"
        threat_id = "2147928809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "argumentum.info/wp-includes/js/jquery/jquery-migrate.min.js" wide //weight: 2
        $x_1_2 = "POST.php?passwordenter" wide //weight: 1
        $x_1_3 = "Local\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_4 = "WindowsApplication710.Resources" ascii //weight: 1
        $x_1_5 = "get_RootDirectory" ascii //weight: 1
        $x_1_6 = "$83e17252-1a27-46c6-8ba1-65c2c91b90d0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SO_2147931331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SO!MTB"
        threat_id = "2147931331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 08 91 1f 1a 59 1f 1f 58 1f 15 59 1e 59 1f 21 59 d2 6f 0a 00 00 0a 08 17 58 0c 08 06 8e 69 32 de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KeyLogger_SEDA_2147935236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogger.SEDA!MTB"
        threat_id = "2147935236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 28 ?? 00 00 0a 72 2a 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 11 05 28 ?? 00 00 0a 72 3c 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7e 16 00 00 04 19 73 10 00 00 0a 0d 09 6f ?? 00 00 0a 69 13 07 09 11 05 6f ?? 00 00 0a 16 73 13 00 00 0a 0b 07 11 04 7e 15 00 00 04 16 94 11 07 6f ?? 00 00 0a 26 72 ?? ?? ?? 70 13 06 72 ?? ?? ?? 70 0a 11 04 28 ?? 00 00 06 26 08 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

