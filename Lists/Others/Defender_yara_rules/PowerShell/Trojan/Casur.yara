rule Trojan_PowerShell_Casur_CS_2147745268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Casur.CS!eml"
        threat_id = "2147745268"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Casur"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objWMIService = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2\")" ascii //weight: 1
        $x_1_2 = "objStartup = objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_3 = "objConfig = objStartup.SpawnInstance_" ascii //weight: 1
        $x_1_4 = "objConfig.ShowWindow = HIDDEN_WINDOW" ascii //weight: 1
        $x_1_5 = "objProcess = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\cimv2:Win32_Process\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_Casur_CM_2147747913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Casur.CM!eml"
        threat_id = "2147747913"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Casur"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 70 61 63 65 28 31 30 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 50 00 46 6f 72 20 45 61 63 68 [0-14] 20 49 6e 20 [0-15] 0d 0a [0-15] 20 3d 20 03 20 26 20}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-15] 2c 20 [0-14] 28 22 [0-3] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-14] 2c 20 [0-15] 22 [0-3] 22 2c 20 [0-15] 22 [0-3] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Debug.Print" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

