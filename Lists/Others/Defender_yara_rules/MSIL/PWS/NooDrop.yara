rule PWS_MSIL_NooDrop_2147743637_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/NooDrop!MTB"
        threat_id = "2147743637"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NooDrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[body-fake]" wide //weight: 1
        $x_1_2 = "[title-fake]" wide //weight: 1
        $x_1_3 = "VBoxTray" wide //weight: 1
        $x_1_4 = "vmtoolsd" wide //weight: 1
        $x_1_5 = "VBoxService" wide //weight: 1
        $x_1_6 = "VGAuthService" wide //weight: 1
        $x_1_7 = "procexp64" wide //weight: 1
        $x_1_8 = "ProcessHacker" wide //weight: 1
        $x_1_9 = "vmacthlp" wide //weight: 1
        $x_1_10 = "\\Run.vbs" wide //weight: 1
        $x_1_11 = "SetWshShell=WScript.CreateObject(\"WScript.Shell\")" wide //weight: 1
        $x_1_12 = "WshShell.Run\"C:\\" wide //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_14 = "[activelink-repalce]" wide //weight: 1
        $x_1_15 = "EnableLUA" wide //weight: 1
        $x_1_16 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 1
        $x_1_17 = "%Systemroot%\\System32\\explorer.exe" wide //weight: 1
        $x_1_18 = "[netornative-replace]" wide //weight: 1
        $x_1_19 = "[inj-replace]" wide //weight: 1
        $x_1_20 = "[downloadlink-replace]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

