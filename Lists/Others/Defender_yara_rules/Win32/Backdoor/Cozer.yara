rule Backdoor_Win32_Cozer_A_2147697669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cozer.A!dha"
        threat_id = "2147697669"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cozer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 61 73 6b 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 61 73 6b 5f 64 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b 65 79 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 6f 74 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 6c 65 65 70 5f 74 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 6f 73 74 5f 73 63 72 69 70 74 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {65 78 74 5f 69 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 65 74 5f 75 70 64 61 74 65 5f 69 6e 74 65 72 76 61 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 75 72 72 65 6e 74 5f 74 72 61 6e 73 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_10 = "onclick=\"Accept();\"" ascii //weight: 1
        $x_1_11 = "File {0} has been uploaded" ascii //weight: 1
        $x_1_12 = "File {0} has been downloaded" ascii //weight: 1
        $x_1_13 = "Process (pid:{1}) {0} has been started" ascii //weight: 1
        $x_2_14 = "href\\s*=\\s*(?:[\"'](?<1>[^\"']*)[\"']|(?<1>\\S+))" ascii //weight: 2
        $x_2_15 = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$" ascii //weight: 2
        $n_1000_16 = "Node Agent (head@5acad41)" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

