rule TrojanDropper_Win32_RedPlug_A_2147723370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RedPlug.A!dha"
        threat_id = "2147723370"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RedPlug"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 99 b9 1a 00 00 00 f7 f9 46 80 c2 41 88 54 35 ?? 83 fe 64 7c}  //weight: 10, accuracy: Low
        $x_1_2 = "cplusplus_me" ascii //weight: 1
        $x_1_3 = "Local AppWizard-Generated Applications" ascii //weight: 1
        $x_1_4 = "ForceRemove" ascii //weight: 1
        $x_1_5 = "NoRemove" ascii //weight: 1
        $x_1_6 = "NoRun" ascii //weight: 1
        $x_1_7 = "NoEntireNetwork" ascii //weight: 1
        $x_1_8 = "NoFileMru" ascii //weight: 1
        $x_1_9 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_10 = "NoPlacesBar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

