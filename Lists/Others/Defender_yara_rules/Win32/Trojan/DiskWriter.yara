rule Trojan_Win32_DiskWriter_BI_2147829046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.BI!MTB"
        threat_id = "2147829046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 00 00 10 68 d0 30 41 00 e8 27 28 ff ff 8b d8 6a 00 68 d0 88 41 00 68 00 30 00 00 68 d4 88 41 00 53 e8 1e 29 ff ff 53}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_AD_2147834832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.AD!MTB"
        threat_id = "2147834832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "virus@satinfo.es" ascii //weight: 1
        $x_1_2 = "Keylogger.Bladabindi" ascii //weight: 1
        $x_1_3 = "Malware.Postal" ascii //weight: 1
        $x_1_4 = "Ransom.Servcc" ascii //weight: 1
        $x_1_5 = "Trojan.DistTrack" ascii //weight: 1
        $x_1_6 = "Malware.Zambrano" ascii //weight: 1
        $x_1_7 = "HACK BY DEBUGGER !!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_MKV_2147910218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.MKV!MTB"
        threat_id = "2147910218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 89 55 a8 6a 00 e8 ?? ?? ?? ?? 8b 55 a8 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_MWAA_2147910496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.MWAA!MTB"
        threat_id = "2147910496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 45 ec 89 45 a8 6a 00 e8 ?? ?? ?? ?? 8b 55 a8 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_NEAA_2147910927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.NEAA!MTB"
        threat_id = "2147910927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 a8 81 c2 ?? ?? ?? ?? 2b 55 9c 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_ADW_2147925038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.ADW!MTB"
        threat_id = "2147925038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d7 c1 ea 05 8d 0c 38 89 55 fc 8b 45 d8 01 45 fc 8b c7 c1 e0 04 03 45 e4 33 45 fc 33 c1 89 45 d4 8b 45 d4 29 45 f4 8b 45 e8 29 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_ADW_2147925038_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.ADW!MTB"
        threat_id = "2147925038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b f0 68 a4 e6 41 00 56 ff d7 68 b8 e6 41 00 56 8b d8 ff d7 68 d0 e6 41 00 56 8b f8 ff 15}  //weight: 2, accuracy: High
        $x_3_2 = "Your PC has been deleted by pidHRemastered.exe" ascii //weight: 3
        $x_4_3 = "Malware alert - pidHRemastered.exe" wide //weight: 4
        $x_1_4 = "Are you sure you want to run this" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiskWriter_ADB_2147952318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskWriter.ADB!MTB"
        threat_id = "2147952318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d0 8b c8 c1 fa 10 c1 f9 08 0a d1 8b c8 c1 f9 07 0a d1 0f b6 c8 f6 d2 22 d0 0f b6 d2 0f af d1 88 14 38 40 3b c6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

