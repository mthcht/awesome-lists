rule Worm_Win32_Boychi_A_2147656412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Boychi.A"
        threat_id = "2147656412"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Boychi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avgntmgr.sys" ascii //weight: 1
        $x_1_2 = "avgntdd.sys" ascii //weight: 1
        $x_1_3 = "DeepFrz.sys" ascii //weight: 1
        $x_1_4 = "eeyeh.sys" ascii //weight: 1
        $x_1_5 = "procguard.sys" ascii //weight: 1
        $x_1_6 = "fwdrv.sys" ascii //weight: 1
        $x_1_7 = "inspect.sys" ascii //weight: 1
        $x_1_8 = "pavproc.sys" ascii //weight: 1
        $x_1_9 = "tmcomm.sys" ascii //weight: 1
        $x_1_10 = "vsdatant.sys" ascii //weight: 1
        $x_1_11 = "driversvsdatant.sys" ascii //weight: 1
        $x_1_12 = "AshAvScan.sys" ascii //weight: 1
        $x_1_13 = "wpsdrvnt.sys" ascii //weight: 1
        $x_1_14 = "AVGIDSxx.sys" ascii //weight: 1
        $x_2_15 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_16 = "autorun.inf" ascii //weight: 2
        $x_2_17 = "autorun.exe" ascii //weight: 2
        $x_1_18 = "Outlook Express" ascii //weight: 1
        $x_1_19 = "Microsoft Outlook" ascii //weight: 1
        $x_1_20 = "Software\\Google\\Google Talk\\Accounts" ascii //weight: 1
        $x_1_21 = "Plugin Manager\\skypePM.exe" ascii //weight: 1
        $x_1_22 = "Software\\Microsoft\\MSNMessenger" ascii //weight: 1
        $x_1_23 = "Windows Live Messenger" ascii //weight: 1
        $x_1_24 = "Infect" ascii //weight: 1
        $x_1_25 = "Mobile" ascii //weight: 1
        $x_1_26 = "USB Drive" ascii //weight: 1
        $x_1_27 = "VMware" ascii //weight: 1
        $n_100_28 = "Advisors Assistant\\AdvisorsAssistant.pdb" ascii //weight: -100
        $n_100_29 = "Client Marketing Systems" wide //weight: -100
        $n_100_30 = "Star City Online Game" wide //weight: -100
        $n_100_31 = "Language=TW&Category=Login&Region=886&ServiceName=" wide //weight: -100
        $n_100_32 = "PsychodatOffice.pdb" ascii //weight: -100
        $n_100_33 = "PsychoDat office" wide //weight: -100
        $n_100_34 = "AnVir Task Manager" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_2_*) and 14 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Boychi_A_2147661344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Boychi.A!sys"
        threat_id = "2147661344"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Boychi"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Device\\MSH4DEV2" wide //weight: 1
        $x_1_2 = "\\Driver\\DeepFrz" wide //weight: 1
        $x_2_3 = {68 76 72 44 4d bb 80 00 00 00 53 57 89 41 0c ff d6}  //weight: 2, accuracy: High
        $x_2_4 = {68 6c 61 67 61 bb a0 0f 00 00 53 57 ff d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

