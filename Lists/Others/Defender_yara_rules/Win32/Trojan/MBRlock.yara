rule Trojan_Win32_MBRlock_DAX_2147852650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MBRlock.DAX!MTB"
        threat_id = "2147852650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your disk have a lock!Please input the unlock password!" ascii //weight: 1
        $x_1_2 = "@\\\\.\\\\physicaldrive0" ascii //weight: 1
        $x_1_3 = "Shutdown.exe -s -t 1" ascii //weight: 1
        $x_1_4 = "net user Administrator 1148" ascii //weight: 1
        $x_1_5 = {83 c4 1c 68 04 00 00 80 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 02 00 00 00 bb ?? ?? 40 00 e8 ?? ?? 00 00 83 c4 1c}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 44 24 08 6a ff 50 ff 15 ?? ?? ?? ?? eb 10 8b 4c 24 08 68 e8 03 00 00 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MBRlock_DY_2147852924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MBRlock.DY!MTB"
        threat_id = "2147852924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your disk have a lock!Please input the unlock password!" ascii //weight: 1
        $x_1_2 = "@\\\\.\\\\physicaldrive0" ascii //weight: 1
        $x_1_3 = {55 8b ec 68 02 00 00 80 6a 00 68 01 00 00 00 6a 00 6a 00 6a 00 68 01 00 01 00 68 11 00 01 06 68 12 00 01 52 68 03 00 00 00 bb}  //weight: 1, accuracy: High
        $x_1_4 = {8b 46 1c 68 e8 03 00 00 50 ff 15 ?? ?? ?? 00 c7 46 50 00 00 00 00 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MBRlock_NM_2147897007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MBRlock.NM!MTB"
        threat_id = "2147897007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 05 e0 bd 4c 00 ?? ?? ?? ?? 8d 86 80 04 00 00 3b f0 73 1e 80 66 04 ?? 83 0e ff 83 66 08 ?? c6 46 05 0a a1 ?? ?? ?? ?? 83 c6 24 05 ?? ?? ?? ?? eb de 8d 45 b8}  //weight: 5, accuracy: Low
        $x_1_2 = "\\physicaldrive0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

