rule Trojan_MSIL_DesckVBRAT_GVA_2147971037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRAT.GVA!MTB"
        threat_id = "2147971037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "New-ItemProperty -Path" wide //weight: 1
        $x_1_2 = "Update Drivers NVIDEO" wide //weight: 1
        $x_1_3 = "-WindowStyle Hidden" wide //weight: 1
        $x_1_4 = ".ps1" wide //weight: 1
        $x_1_5 = "\\AppData\\LocalLow\\Daft Sytem (x86)\\" wide //weight: 1
        $x_1_6 = "Program Rules NVIDEO\\Program Rules NVIDEO\\Program Rules NVIDEO\\Program Rules NVIDEO\\" wide //weight: 1
        $x_1_7 = "powershell shutdown -force -restart" wide //weight: 1
        $x_1_8 = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_9 = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DesckVBRAT_GVB_2147971038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRAT.GVB!MTB"
        threat_id = "2147971038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\LocalLow\\debug_runpe.txt" wide //weight: 1
        $x_1_2 = "=== RunPE Debug Log ===" wide //weight: 1
        $x_1_3 = "Data/Hora :" wide //weight: 1
        $x_1_4 = "Loader PID:" wide //weight: 1
        $x_1_5 = "TODAS AS TENTATIVAS FALHARAM" wide //weight: 1
        $x_1_6 = "DLL -> InjectDLL" wide //weight: 1
        $x_1_7 = "EXE -> Process Hollow" wide //weight: 1
        $x_1_8 = "ReadProcessMemory PEB.ImageBase" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

