rule HackTool_Win32_Crack_2147745913_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crack!MTB"
        threat_id = "2147745913"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RarExtInstaller.pdb" ascii //weight: 2
        $x_1_2 = "C:\\NeverShow.txt" ascii //weight: 1
        $x_1_3 = "OnClick" ascii //weight: 1
        $x_1_4 = "repacks.ddns.net" ascii //weight: 1
        $x_1_5 = "repack.me" ascii //weight: 1
        $x_1_6 = "Activation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Crack_2147745913_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crack!MTB"
        threat_id = "2147745913"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cracker" ascii //weight: 1
        $x_1_2 = "*START PATCHING*" ascii //weight: 1
        $x_1_3 = "OFFSET PATCH" ascii //weight: 1
        $x_1_4 = "SEARCH & REPLACE PATCH" ascii //weight: 1
        $x_1_5 = "PATCHING DONE" ascii //weight: 1
        $x_1_6 = "Patchtarget" ascii //weight: 1
        $x_1_7 = "REGISTRY PATCH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Crack_2147745913_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crack!MTB"
        threat_id = "2147745913"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "repacks.ddns.net" ascii //weight: 1
        $x_1_2 = "s:\\IDM_projects\\IDMIECC2\\64bit\\ReleaseMinDependency\\IDMIECC64.pdb" ascii //weight: 1
        $x_1_3 = "Activate.cmd" ascii //weight: 1
        $x_1_4 = "PureFlat.tbi" ascii //weight: 1
        $x_1_5 = "Tonek Inc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Crack_AMTB_2147933412_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crack!AMTB"
        threat_id = "2147933412"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Selenite.pdb" ascii //weight: 1
        $x_1_2 = "SeleniteFakeGrabIPGun.txt" ascii //weight: 1
        $x_1_3 = "SeleniteGrabIDGun.txt" ascii //weight: 1
        $x_1_4 = "SeleniteRoomInfo.txt" ascii //weight: 1
        $x_1_5 = "Selenite.dll" ascii //weight: 1
        $x_1_6 = "https://iidk.online" ascii //weight: 1
        $x_1_7 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 61 00 74 00 62 00 6f 00 78 00 2e 00 6d 00 6f 00 65 00 2f 00 [0-15] 2e 00 6d 00 70 00 33 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f [0-15] 2e 6d 70 33}  //weight: 1, accuracy: Low
        $n_100_9 = "Uninst.exe" ascii //weight: -100
        $n_100_10 = "Uninstaller.exe" ascii //weight: -100
        $n_100_11 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (7 of ($x*))
}

