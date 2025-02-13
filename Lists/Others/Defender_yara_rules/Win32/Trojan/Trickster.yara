rule Trojan_Win32_Trickster_A_2147730835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickster.A"
        threat_id = "2147730835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 73 04 8b 13 83 c3 08 03 96 00 00 40 00 8d 86 00 00 40 00 89 55 cc e8 8f fd ff ff 8b 45 cc 81 fb 20 95 41 00 89 86 00 00 40 00 72 d3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f4 8d 50 0c 8b 45 0c 2b 45 f4 8d 48 ff 8b 45 08 01 c8 0f b6 00 88 82 80 81 41 00 83 45 f4 01 8b 45 f4 3b 45 0c 7c d7}  //weight: 1, accuracy: High
        $x_1_3 = "1.HKe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickster_DD_2147748437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickster.DD!MSR"
        threat_id = "2147748437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickster"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillTimer" ascii //weight: 1
        $x_1_2 = "shellexecutea" ascii //weight: 1
        $x_1_3 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "Trainer_Stronghold" ascii //weight: 1
        $x_1_6 = "Trainer_Desperados.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

