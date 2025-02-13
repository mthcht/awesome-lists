rule Trojan_Win64_Disdroth_LK_2147845673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disdroth.LK!MTB"
        threat_id = "2147845673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disdroth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 84 bd 07 00 00 48 89 c1 48 c1 e9 34 83 e1 3f 42 8a 0c 39 88 4b 01 48 83 ff 02 0f 86 ae 07 00 00 48 89 c1 48 c1 e9 2e 83 e1 3f 42 8a 0c 39 88 4b 02 48 83 ff 03 0f 84 9f 07 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 05 e2 e3 01 00 ba 40 00 00 00 41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe c0 86 05 00 eb 2d 4c 8b 15 b9 e3 01 00 eb b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Disdroth_EM_2147848358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disdroth.EM!MTB"
        threat_id = "2147848358"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disdroth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ba 40 00 00 00 41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe 00 07 05 00 eb 89}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Disdroth_EM_2147848358_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disdroth.EM!MTB"
        threat_id = "2147848358"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disdroth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Tony Stark\\.rustup\\toolchains" ascii //weight: 1
        $x_1_2 = "Prioritystream_iddependency" ascii //weight: 1
        $x_1_3 = "Pingackpayload" ascii //weight: 1
        $x_1_4 = "_desktop.pdb" ascii //weight: 1
        $x_1_5 = "\\cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

