rule Trojan_MSIL_BypassUAC_GNF_2147898086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.GNF!MTB"
        threat_id = "2147898086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 0a 02 28 ?? ?? ?? 06 0b 07 8e 69 8d 1d 00 00 01 0c 16 0d 2b 13 08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_SGA_2147904862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.SGA!MTB"
        threat_id = "2147904862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Dofus2\\Module_Ankama_Connection.dat" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_SG_2147906456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.SG!MTB"
        threat_id = "2147906456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AbaddonStub.exe" ascii //weight: 1
        $x_1_2 = "HTTPDebuggerBrowser.dll" wide //weight: 1
        $x_1_3 = "/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_RP_2147913282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.RP!MTB"
        threat_id = "2147913282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 03 00 20 04 00 00 00 fe 01 39 05 00 00 00 38 05 00 00 00 38 5e ff ff ff 28 20 00 00 06 28 1f 00 00 06 60 28 21 00 00 06 60 28 22 00 00 06 60 28 23 00 00 06 60 39 06 00 00 00 14 28 24 00 00 0a dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_NB_2147916239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.NB!MTB"
        threat_id = "2147916239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\root\\SecurityCenter2" ascii //weight: 3
        $x_2_2 = "Select * from AntivirusProduct" ascii //weight: 2
        $x_1_3 = "WebEye.Controls.WinForms.WebCameraControl.dll" ascii //weight: 1
        $x_1_4 = "/send-passwords" ascii //weight: 1
        $x_1_5 = "netsh firewall delete allowedprogram" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "ZT_RAT" ascii //weight: 1
        $x_1_8 = "/get-remote-shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_NC_2147918386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.NC!MTB"
        threat_id = "2147918386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ZT_RAT_Client.Resources" ascii //weight: 3
        $x_2_2 = "Select * from AntivirusProduct" ascii //weight: 2
        $x_1_3 = "/get-clipboard-text" ascii //weight: 1
        $x_1_4 = "/send-passwords" ascii //weight: 1
        $x_1_5 = "netsh firewall delete allowedprogram" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_NG_2147925555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.NG!MTB"
        threat_id = "2147925555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e1ede26c-6645-49cc-9c1e-52d132f7a571" ascii //weight: 2
        $x_1_2 = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "System32\\fodhelper.exe" ascii //weight: 1
        $x_1_4 = "VM DETECTED" ascii //weight: 1
        $x_1_5 = "Sandbox DETECTED" ascii //weight: 1
        $x_1_6 = "DOWNLOADFILE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BypassUAC_PAHI_2147961190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BypassUAC.PAHI!MTB"
        threat_id = "2147961190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}" wide //weight: 1
        $x_1_2 = "root\\CIMV2" wide //weight: 1
        $x_1_3 = "NoOneComeALive" wide //weight: 1
        $x_1_4 = "start /C C:\\Windows\\System32\\fodhelper.exe" wide //weight: 1
        $x_2_5 = "rootkit dropper" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

