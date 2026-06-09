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

rule Trojan_MSIL_DesckVBRAT_GVD_2147971207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRAT.GVD!MTB"
        threat_id = "2147971207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 1e 00 00 06 28 0d 00 00 06 28 0a 00 00 06 13 00 38 00 00 00 00 28 15 00 00 0a 11 00 6f 16 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {11 04 02 16 02 8e 69 6f 0f 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DesckVBRAT_GVE_2147971208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRAT.GVE!MTB"
        threat_id = "2147971208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 08 13 05 14 13 08 11 05 8e 69 1e 5b 13 0c 11 05 73 13 00 00 0a 73 7a 00 00 06 13 0d 16 13 16 38 23 00 00 00 11 0d 6f 7e 00 00 06 13 17 11 0d 6f 7e 00 00 06 13 18 11 04 11 17 11 18 6f 33 00 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff 11 0d 6f 7f 00 00 06 11 04 80 0c 00 00 04 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DesckVBRAT_GVF_2147971209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DesckVBRAT.GVF!MTB"
        threat_id = "2147971209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesckVBRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 08 13 05 14 13 08 11 05 8e 69 1e 5b 13 0c 11 05 73 2a 00 00 0a 73 6c 08 00 06 13 0d 16 13 16 38 23 00 00 00 11 0d 6f 70 08 00 06 13 17 11 0d 6f 70 08 00 06 13 18 11 04 11 17 11 18 6f a7 01 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff 11 0d 6f 71 08 00 06 11 04 80 f7 02 00 04 dd 0d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

