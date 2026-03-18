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

rule Trojan_Win32_SysWiper_GX_2147964687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.GX!MTB"
        threat_id = "2147964687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FileEnc.pdb" ascii //weight: 10
        $x_10_2 = "\\GLOBALROOT" wide //weight: 10
        $x_10_3 = "C:\\path\\to\\file.txt" ascii //weight: 10
        $x_10_4 = "File overwritten and deleted successfully" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_GY_2147964688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.GY!MTB"
        threat_id = "2147964688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Error opening drive. Code:" ascii //weight: 10
        $x_10_2 = "Drive handle opened successfully" ascii //weight: 10
        $x_10_3 = "Successfully read first sector" ascii //weight: 10
        $x_10_4 = "Checking privileges..." ascii //weight: 10
        $x_10_5 = "Program is NOT running as Administrator." ascii //weight: 10
        $x_10_6 = "Program running with Administrator privileges" ascii //weight: 10
        $x_10_7 = "Program finished safely." ascii //weight: 10
        $x_10_8 = "Stack around the variable" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_GZ_2147964689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.GZ!MTB"
        threat_id = "2147964689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_Wiper.pdb" ascii //weight: 10
        $x_10_2 = ".\\PhysicalDrive" wide //weight: 10
        $x_10_3 = "Unable to display RTC Message." wide //weight: 10
        $x_10_4 = "Physical drive(e.g. 0):" wide //weight: 10
        $x_10_5 = "Path:" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_GK_2147964690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.GK!MTB"
        threat_id = "2147964690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Not running with admin privileges." ascii //weight: 10
        $x_10_2 = "Running with admin privileges." ascii //weight: 10
        $x_10_3 = "Stack memory was corrupted" ascii //weight: 10
        $x_10_4 = "A local variable was used before it was initialized" ascii //weight: 10
        $x_10_5 = "causing loss of data" ascii //weight: 10
        $x_10_6 = "\\GLOBALROOT" wide //weight: 10
        $x_10_7 = "Unable to display RTC Message" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_DE_2147964699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.DE!MTB"
        threat_id = "2147964699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "89"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {48 89 4d b0 48 c7 45 b8 03 00 00 00 4c 8d 45 b0 8b d0 48 8d 4c 24 50 e8 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d c7 5a 00 00 48 89 4d b0 48 c7 45 b8 03 00 00 00 4c 8d 45 b0 8b d0 48 8d 4c 24 70 e8 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d a2 5a 00 00 48 89 4d b0 48 c7 45 b8 03 00 00 00 4c 8d 45 b0 8b d0 48 8d 4d}  //weight: 50, accuracy: Low
        $x_10_2 = "Not running with admin privileges." ascii //weight: 10
        $x_10_3 = "Running with admin privileges." ascii //weight: 10
        $x_1_4 = "directory_iterator::operator++" ascii //weight: 1
        $x_1_5 = "recursive_directory_iterator::recursive_directory_iterator" ascii //weight: 1
        $x_1_6 = "MultiByteToWideChar" ascii //weight: 1
        $x_1_7 = "WideCharToMultiByte" ascii //weight: 1
        $x_1_8 = "memmove" ascii //weight: 1
        $x_1_9 = "memcpy" ascii //weight: 1
        $x_10_10 = "CreateFile2" ascii //weight: 10
        $x_1_11 = "Sleep" ascii //weight: 1
        $x_1_12 = "remove" ascii //weight: 1
        $x_1_13 = "status" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_GA_2147965036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.GA!MTB"
        threat_id = "2147965036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.wipe_server" ascii //weight: 1
        $x_1_2 = "main.srv_handler" ascii //weight: 1
        $x_1_3 = "go:textfipsstart" ascii //weight: 1
        $x_1_4 = "Wiping server.." ascii //weight: 1
        $x_1_5 = "wipe.StopServer" ascii //weight: 1
        $x_1_6 = "wipe.KillServer" ascii //weight: 1
        $x_1_7 = "wipe.StartServer" ascii //weight: 1
        $x_1_8 = "Print out config and exit" ascii //weight: 1
        $x_1_9 = "Print out version and exit" ascii //weight: 1
        $x_1_10 = "The path to the Rust Auto Wipe config file." ascii //weight: 1
        $x_1_11 = "-cfg= --cfg -cfg <path> > Path to config file override." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SysWiper_GB_2147965037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysWiper.GB!MTB"
        threat_id = "2147965037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /e:ON /v:OFF /d /c \"batch file arguments are invalid" ascii //weight: 1
        $x_1_2 = "Windows file names may not contain `\"`" ascii //weight: 1
        $x_1_3 = "Traversalwiper-walk-dispatcher" ascii //weight: 1
        $x_1_4 = "wiper.pdb" ascii //weight: 1
        $x_1_5 = "WiperError" ascii //weight: 1
        $x_1_6 = "description() is deprecated; use Display" ascii //weight: 1
        $x_1_7 = "crossterm::cursor::Hide" ascii //weight: 1
        $x_1_8 = "/Enter/Backspace - navigatesrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

