rule Trojan_Win64_Reconyc_2147807388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reconyc.lmnq!MTB"
        threat_id = "2147807388"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "lmnq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a a0 db df 45 f5 33 b6 ?? ?? ?? ?? 6b e5 59 d3 e0 33 a8 ?? ?? ?? ?? e0 f1 64 b7 02 30 8a ?? ?? ?? ?? 7c e4}  //weight: 10, accuracy: Low
        $x_2_2 = "sloader.exe" ascii //weight: 2
        $x_2_3 = "ShellExecuteExW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Reconyc_AMAC_2147926300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reconyc.AMAC!MTB"
        threat_id = "2147926300"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sameconcentrate.exe" ascii //weight: 10
        $x_1_2 = "wextract.pdb" ascii //weight: 1
        $x_1_3 = "REBOOT" ascii //weight: 1
        $x_1_4 = "DecryptFileA" ascii //weight: 1
        $x_1_5 = "msdownld.tmp" ascii //weight: 1
        $x_1_6 = "C:\\TEMP\\IXP000.TMP\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Reconyc_NR_2147958048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reconyc.NR!MTB"
        threat_id = "2147958048"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e9 14 00 00 00 8b 85 ?? ?? ff ff 48 89 c1 83 c0 01 89 85 ?? ?? ff ff eb d0 8b 85 ?? ?? ff ff 48 8b}  //weight: 2, accuracy: Low
        $x_1_2 = {48 89 44 24 20 48 8d 85 ?? fd ff ff 49 89 c1 8b 85 ?? fd ff ff 49 89 c0 48 8b 85 ?? fd ff ff 49 89 c3 48 8b 85 ?? fd ff ff 49 89 c2 4c 89 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Reconyc_GVC_2147963305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reconyc.GVC!MTB"
        threat_id = "2147963305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "570015700256001netsh" ascii //weight: 1
        $x_1_2 = "Payload decrypted:" ascii //weight: 1
        $x_1_3 = "advfirewallfirewalladdruledir=inaction=allowprotocol=TCP" ascii //weight: 1
        $x_15_4 = "Registry Run KeyGhost Scheduled TaskWinlogon UserinitCOM HijackingGlobal\\StealthPackerMutex_9A8B7C" ascii //weight: 15
        $x_15_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WinlogonUserinit" ascii //weight: 15
        $x_15_6 = "schtasks/Create/F/SCONLOGON/TN/TR/RLHIGHEST" ascii //weight: 15
        $x_15_7 = "schtasks/Delete/F/TN/Create/SCONLOGON/TR/RLHIGHESTE" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_15_*) and 3 of ($x_1_*))) or
            ((3 of ($x_15_*))) or
            (all of ($x*))
        )
}

