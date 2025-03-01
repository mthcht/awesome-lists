rule Worm_Win32_Mydoom_PA_2147741207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mydoom.PA!MTB"
        threat_id = "2147741207"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mydoom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\WINDOWS\\SYSTEM32\\ctfmen.exe" ascii //weight: 1
        $x_1_2 = ":\\WINDOWS\\SYSTEM32\\smnss.exe" ascii //weight: 1
        $x_1_3 = ":\\WINDOWS\\SYSTEM32\\satornas.dll" ascii //weight: 1
        $x_1_4 = ":\\WINDOWS\\SYSTEM32\\grcopy.dll" ascii //weight: 1
        $x_1_5 = "autostart_bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mydoom_PB_2147741305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mydoom.PB!MTB"
        threat_id = "2147741305"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mydoom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netbios_infected" ascii //weight: 1
        $x_1_2 = "mydoom_infected" ascii //weight: 1
        $x_1_3 = "Added copy to statup" ascii //weight: 1
        $x_1_4 = "biscanwormmark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

