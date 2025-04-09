rule Trojan_Win64_ClassCuts_A_2147933297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClassCuts.A!dha"
        threat_id = "2147933297"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClassCuts"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "changeshell" ascii //weight: 100
        $x_100_2 = "savedata" ascii //weight: 100
        $x_100_3 = "getfile" ascii //weight: 100
        $x_100_4 = "postfile" ascii //weight: 100
        $x_100_5 = "NoData" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClassCuts_B_2147933298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClassCuts.B!dha"
        threat_id = "2147933298"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClassCuts"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Client ready!" ascii //weight: 100
        $x_100_2 = "GetTasks" ascii //weight: 100
        $x_100_3 = "Results=" ascii //weight: 100
        $x_100_4 = "NO_DATA" ascii //weight: 100
        $x_100_5 = "STATUS_OK" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClassCuts_C_2147933299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClassCuts.C!dha"
        threat_id = "2147933299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClassCuts"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {48 89 4b 68 c6 83 88 00 00 00 01 48 8b c3 48 83 c4 20 5b c3}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClassCuts_D_2147938290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClassCuts.D!dha"
        threat_id = "2147938290"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClassCuts"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delkill /F /IM explENT_USER\\Softwar" ascii //weight: 1
        $x_1_2 = "[+] ShortTimer and FailCounter changed." ascii //weight: 1
        $x_1_3 = "[+] Endpoint changed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

