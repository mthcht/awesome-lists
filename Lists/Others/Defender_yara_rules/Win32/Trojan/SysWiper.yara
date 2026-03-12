rule Trojan_Win32_SysWiper_DA_2147964593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.DA!MTB"
        threat_id = "2147964593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "github.com/0x9ef/go-wiper/wipe" ascii //weight: 10
        $x_5_2 = "Data will be overwrited with zeroes" ascii //weight: 5
        $x_1_3 = "data wiping" ascii //weight: 1
        $x_10_4 = "IMRAN_DESTROYED_YOUR_OS_HAHAHA" ascii //weight: 10
        $x_6_5 = "virus scan finished lol" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SysWiper_DB_2147964594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.DB!MTB"
        threat_id = "2147964594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "MalwareStartup" ascii //weight: 20
        $x_20_2 = "malware.lnk" ascii //weight: 20
        $x_20_3 = "MyWiperMalware" ascii //weight: 20
        $x_20_4 = "MyMalware" ascii //weight: 20
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "Persistence added successfully" ascii //weight: 1
        $x_1_7 = "Free disk space wiped successfully" ascii //weight: 1
        $x_1_8 = "Error opening physical drive for MBR wiping" ascii //weight: 1
        $x_1_9 = "Error writing to drive to wipe MBR" ascii //weight: 1
        $x_1_10 = "encrypted and deleted" ascii //weight: 1
        $x_1_11 = "Scheduled task for persistence added" ascii //weight: 1
        $x_1_12 = "schtasks /create /tn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SysWiper_DC_2147964595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.DC!MTB"
        threat_id = "2147964595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wipe STARTED" ascii //weight: 10
        $x_1_2 = ".\\PhysicalDrive" ascii //weight: 1
        $x_1_3 = "physical drive will be lost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_DD_2147964596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.DD!MTB"
        threat_id = "2147964596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Success: MBR has been overwritten!" ascii //weight: 10
        $x_1_2 = ".\\PhysicalDrive" ascii //weight: 1
        $x_1_3 = "Failed to overwrite the MBR" ascii //weight: 1
        $x_1_4 = "Run as Administrator" ascii //weight: 1
        $x_1_5 = "Unable to access the disk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

