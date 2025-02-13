rule Trojan_Win32_Growpia_A_2147761503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Growpia.A!MTB"
        threat_id = "2147761503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Growpia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Growtopia" ascii //weight: 1
        $x_1_2 = "Local\\Growtopia\\save.dat" ascii //weight: 1
        $x_1_3 = "SaveForwarder/save.php" ascii //weight: 1
        $x_1_4 = {5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 2c 22 90 01 02 5c 55 73 65 72 73 5c 90 02 15 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 90 02 25 2e 65 78 65 22 20 2d 73}  //weight: 1, accuracy: High
        $x_1_5 = "\\Windows\\system32\\emptyregdb.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Growpia_A_2147761692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Growpia.A!!Growpia.gen!MTB"
        threat_id = "2147761692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Growpia"
        severity = "Critical"
        info = "Growpia: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Growtopia" ascii //weight: 1
        $x_1_2 = "Local\\Growtopia\\save.dat" ascii //weight: 1
        $x_1_3 = "SaveForwarder/save.php" ascii //weight: 1
        $x_1_4 = {5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 2c 22 90 01 02 5c 55 73 65 72 73 5c 90 02 15 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 90 02 25 2e 65 78 65 22 20 2d 73}  //weight: 1, accuracy: High
        $x_1_5 = "\\Windows\\system32\\emptyregdb.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

