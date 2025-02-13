rule Trojan_MSIL_Recon_YA_2147731937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Recon.YA!MTB"
        threat_id = "2147731937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Recon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
        $x_1_2 = "gwmi -query \"Select TotalPhysicalMemory from Win32_ComputerSystem\"" wide //weight: 1
        $x_1_3 = "gwmi -Class win32_Processor | select NumberOfCores" wide //weight: 1
        $x_1_4 = "gwmi -query \"select * from win32_BIOS where SMBIOSBIOSVERSION LIKE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

