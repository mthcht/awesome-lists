rule Trojan_Win32_MasqProcessLaunchLolbins_B_2147778155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MasqProcessLaunchLolbins.B!sync"
        threat_id = "2147778155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MasqProcessLaunchLolbins"
        severity = "Critical"
        info = "sync: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 73 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $n_10_5 = "qprotection sense" wide //weight: -10
        $n_10_6 = "DataManagementGateway" wide //weight: -10
        $n_10_7 = "schtasks.exe /delete" wide //weight: -10
        $n_10_8 = "\\iCloud\\" wide //weight: -10
        $n_10_9 = "iCloudMigrate.exe" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_MasqProcessLaunchLolbins_C_2147778156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MasqProcessLaunchLolbins.C!sync"
        threat_id = "2147778156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MasqProcessLaunchLolbins"
        severity = "Critical"
        info = "sync: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 68 00 6f 00 61 00 6d 00 69 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MasqProcessLaunchLolbins_D_2147778582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MasqProcessLaunchLolbins.D!sync"
        threat_id = "2147778582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MasqProcessLaunchLolbins"
        severity = "Critical"
        info = "sync: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 61 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

