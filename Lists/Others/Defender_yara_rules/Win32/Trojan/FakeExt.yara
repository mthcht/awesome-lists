rule Trojan_Win32_FakeExt_B_2147894009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeExt.B!MTB"
        threat_id = "2147894009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeExt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DIRCREATE ( @APPDATADIR & \"\\" wide //weight: 2
        $x_2_2 = "FILEINSTALL ( \"C:\\Users\\" wide //weight: 2
        $x_2_3 = ".exe\" , 1 )" wide //weight: 2
        $x_2_4 = "SHELLEXECUTE ( @APPDATADIR & \"\\" wide //weight: 2
        $x_2_5 = ".exe\" , @APPDATADIR & \"\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeExt_NA_2147913056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeExt.NA!MTB"
        threat_id = "2147913056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeExt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SHELLEXECUTE ( @WORKINGDIR & \"-\\" ascii //weight: 5
        $x_5_2 = "SHELLEXECUTE ( @WORKINGDIR & \"-\\NdSVissza.exe\" )" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

