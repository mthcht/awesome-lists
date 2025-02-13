rule Trojan_PowerShell_DCRecon_A_2147782600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DCRecon.A!ibt"
        threat_id = "2147782600"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DCRecon"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe /c powershell.exe" wide //weight: 10
        $x_5_2 = "[system.directoryservices.activedirectory.domain]::getcurrentdomain().domaincontrollers" wide //weight: 5
        $x_5_3 = "select-propertyname,ipaddress,osversion" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

