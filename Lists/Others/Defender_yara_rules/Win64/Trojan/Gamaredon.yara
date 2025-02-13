rule Trojan_Win64_Gamaredon_2147841655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gamaredon.psyF!MTB"
        threat_id = "2147841655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyF: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {48 c7 c1 01 00 00 80 e8 ?? ?? ?? ff 4c 8d 05 ff 0c 00 00 48 8d 15 00 0d 00 00 48 c7 c1 01 00 00 80 e8 cc fd ff ff 4c 8d 8c 24 e0 00 00 00 4c 8d}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gamaredon_ZA_2147903804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gamaredon.ZA!MTB"
        threat_id = "2147903804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= createobject(\"wscript.shell\")" ascii //weight: 1
        $x_10_2 = ".Run \"ipconfig /flushdns\", 0, TRUE" ascii //weight: 10
        $x_10_3 = {2e 52 75 6e 20 22 77 73 63 72 69 70 74 2e 65 78 65 20 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c [0-32] 2e 64 6c 6c 20 2f 2f 65 3a 56 42 53 63 72 69 70 74 20 2f 2f 62 22 2c 20 30 2c 20 54 52 55 45}  //weight: 10, accuracy: Low
        $x_1_4 = ".DeleteFile(\"C:\\myapp.exe\")" ascii //weight: 1
        $x_1_5 = ".DeleteFile(\"C:\\Documents and Settings\\Administrator\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

