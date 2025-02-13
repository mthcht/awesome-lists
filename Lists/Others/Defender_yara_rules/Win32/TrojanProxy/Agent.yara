rule TrojanProxy_Win32_Agent_E_2147800571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Agent.E"
        threat_id = "2147800571"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6f 74 46 69 6c 65 48 61 73 68 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 00 00 2e 69 63 73 00 00 00 00 44 6e 73 46 6c 75 73 68 52 65 73 6f 6c 76 65 72 43 61 63 68 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 4f 53 54 00 00 00 00 41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30 00 00 00 00 4d 53 49 45 36 00 00 00 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 5f 21 4d 53 4e 44 53 23 31 21 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Agent_BS_2147804192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Agent.BS"
        threat_id = "2147804192"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "version=%d&cansend=%d&updated=%d&uuid=%s" ascii //weight: 4
        $x_3_2 = "%s/bserv/bserv.php?%s" ascii //weight: 3
        $x_2_3 = "c://2.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Agent_A_2147804288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Agent.A!MTB"
        threat_id = "2147804288"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bikfir.dll" ascii //weight: 10
        $x_10_2 = "k.dilmosofroad.com" ascii //weight: 10
        $x_5_3 = "25f07256-3b46-4531-aa3e-e1729d9aa7cb" ascii //weight: 5
        $x_5_4 = "60f8896b-a437-4e79-9e29-96522ca88c4c" ascii //weight: 5
        $x_10_5 = {ac c0 c0 03 aa e2 f9 61 c9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

