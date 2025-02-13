rule Trojan_O97M_Iscodtas_B_2147729643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Iscodtas.B"
        threat_id = "2147729643"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Iscodtas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 63 68 74 61 73 6b 73 [0-16] 20 2f 63 72 65 61 74 65 20}  //weight: 1, accuracy: Low
        $n_100_2 = "MsgBox " ascii //weight: -100
        $n_100_3 = "MsgBox(" ascii //weight: -100
        $n_100_4 = "txt >>galist.txt" ascii //weight: -100
        $n_100_5 = "C:\\Program Files\\D_Appl\\Z147\\bat\\AATeikiReboot.bat" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_O97M_Iscodtas_CO_2147745415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Iscodtas.CO!MTB"
        threat_id = "2147745415"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Iscodtas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WScript.Shell" ascii //weight: 1
        $x_1_2 = "%appdata%\\" ascii //weight: 1
        $x_1_3 = "schtasks /Create" ascii //weight: 1
        $x_1_4 = ".run(\"cmd.exe /c timeout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

