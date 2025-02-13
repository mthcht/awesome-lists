rule Virus_Win32_Delemon_A_2147575005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Delemon.A!sys"
        threat_id = "2147575005"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Delemon"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZwDeleteFile" ascii //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" wide //weight: 1
        $x_1_3 = "MEMSCAN" wide //weight: 1
        $x_1_4 = "Avg7Core" wide //weight: 1
        $x_1_5 = "AVGNT" wide //weight: 1
        $x_1_6 = "BDFDLL" wide //weight: 1
        $x_1_7 = "Darkspy" wide //weight: 1
        $x_1_8 = "ExpScaner" wide //weight: 1
        $x_1_9 = "hooksys" wide //weight: 1
        $x_1_10 = "KAV_" wide //weight: 1
        $x_1_11 = "KvMemon" wide //weight: 1
        $x_1_12 = "MINIKAV" wide //weight: 1
        $x_1_13 = "NaiAvFilter" wide //weight: 1
        $x_1_14 = "NAVAP" wide //weight: 1
        $x_1_15 = "NAVENG" wide //weight: 1
        $x_1_16 = "nod32drv" wide //weight: 1
        $x_1_17 = "PandaSoftware" wide //weight: 1
        $x_1_18 = "PAVDRV" wide //weight: 1
        $x_1_19 = "PavProtect" wide //weight: 1
        $x_1_20 = "PROFOS" wide //weight: 1
        $x_1_21 = "SHLDDRV" wide //weight: 1
        $x_1_22 = "SYMEVENT" wide //weight: 1
        $x_1_23 = "v3engine" wide //weight: 1
        $x_1_24 = "VETFDDNT" wide //weight: 1
        $x_1_25 = "VetMonNT" wide //weight: 1
        $x_1_26 = "VSAPINT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (24 of ($x*))
}

