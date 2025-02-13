rule TrojanDownloader_Win32_Scar_C_2147638316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Scar.C"
        threat_id = "2147638316"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Run\\360saft" ascii //weight: 1
        $x_1_2 = "firehackr@qq.com" ascii //weight: 1
        $x_1_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c ?? 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {30 30 30 2b 2b 2b ?? 66 69 72 65 68 61 63 6b 72 ?? 73 6d 74 70 2e 71 71 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Scar_D_2147653807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Scar.D"
        threat_id = "2147653807"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "305"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "ZwLoadDriver" ascii //weight: 100
        $x_100_2 = "\\registry\\machine\\system\\CurrentControlSet\\Services\\" ascii //weight: 100
        $x_100_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_100_4 = "\\\\.\\mybr" ascii //weight: 100
        $x_1_5 = "V3LTray.exe" ascii //weight: 1
        $x_1_6 = "V3LSvc.exe" ascii //weight: 1
        $x_1_7 = "V3LExec.exe" ascii //weight: 1
        $x_1_8 = "AYAgent.aye" ascii //weight: 1
        $x_1_9 = "AYServiceNT.aye" ascii //weight: 1
        $x_1_10 = "NaverAdminAPI.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 5 of ($x_1_*))) or
            ((4 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Scar_ARA_2147916355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Scar.ARA!MTB"
        threat_id = "2147916355"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 84 2a d4 54 40 00 8b fe 34 01 83 c9 ff 88 82 d4 54 40 00 33 c0 42 f2 ae f7 d1 49 3b d1 72 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

