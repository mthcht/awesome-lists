rule TrojanDropper_Win64_XMRig_CM_2147963892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XMRig.CM!MTB"
        threat_id = "2147963892"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "echo File deleted successfully." ascii //weight: 2
        $x_2_2 = "del \"%~f0\"" ascii //weight: 2
        $x_2_3 = "delete_self.bat" ascii //weight: 2
        $x_2_4 = "/q /c start %windir%\\explorer _ & _\\explorer.exe" wide //weight: 2
        $x_2_5 = "kernel32 .dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

