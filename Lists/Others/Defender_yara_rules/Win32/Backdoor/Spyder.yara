rule Backdoor_Win32_Spyder_C_2147967446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spyder.C!MTB"
        threat_id = "2147967446"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 04 3e 88 04 0e 46 3b 35 ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Spyder_DA_2147967470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spyder.DA!MTB"
        threat_id = "2147967470"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/spyder/smile.php" ascii //weight: 10
        $x_10_2 = "/cpidr/balloon.php" ascii //weight: 10
        $x_1_3 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "1.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Spyder_DB_2147967471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spyder.DB!MTB"
        threat_id = "2147967471"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT AntivirusProduct FROM Win32_ComputerSystem" ascii //weight: 1
        $x_1_2 = "D:\\spyder\\" ascii //weight: 1
        $x_1_3 = "Application Data\\Compser\\MSDefender.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Spyder_DC_2147967472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spyder.DC!MTB"
        threat_id = "2147967472"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT AntivirusProduct FROM Win32_ComputerSystem" ascii //weight: 1
        $x_1_2 = "VMware detected" ascii //weight: 1
        $x_1_3 = "Analysis tool window detected" ascii //weight: 1
        $x_1_4 = "QEMU detected" ascii //weight: 1
        $x_1_5 = "VirtualBox detected" ascii //weight: 1
        $x_1_6 = "fiddler.exe" ascii //weight: 1
        $x_1_7 = "balloon.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

