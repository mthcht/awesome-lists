rule Trojan_Win32_Fakespy_C_2147626359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakespy.C"
        threat_id = "2147626359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".us - stopped sending" ascii //weight: 1
        $x_1_2 = ":delcycle" ascii //weight: 1
        $x_1_3 = "Delete spyware" ascii //weight: 1
        $x_1_4 = "/secure/index_new.php?id=" ascii //weight: 1
        $x_1_5 = "License_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Fakespy_C_2147626359_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakespy.C"
        threat_id = "2147626359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".us - stopped sending" ascii //weight: 1
        $x_1_2 = ":delcycle" ascii //weight: 1
        $x_1_3 = "Delete spyware" ascii //weight: 1
        $x_1_4 = "/secure/index_new.php?id=" ascii //weight: 1
        $x_1_5 = "License_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fakespy_C_2147626359_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakespy.C"
        threat_id = "2147626359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "instructionsText3\">Click" ascii //weight: 1
        $x_1_2 = "javascript:RunAntivirus()" ascii //weight: 1
        $x_1_3 = "blocked forever.</b><br>" ascii //weight: 1
        $x_1_4 = {70 75 67 61 6c 6b 61 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

