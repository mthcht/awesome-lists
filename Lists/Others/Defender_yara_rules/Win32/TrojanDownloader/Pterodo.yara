rule TrojanDownloader_Win32_Pterodo_A_2147720201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pterodo.A"
        threat_id = "2147720201"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 48 14 fd 43 03 00 81 c1 c3 9e 26 00 89 48 14 c1 e9 10 81 e1 ff 7f 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://adobe.update-service.net/index.php?comp=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pterodo_B_2147720202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pterodo.B"
        threat_id = "2147720202"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "urltoload={" ascii //weight: 1
        $x_1_2 = " /css.php?id=" ascii //weight: 1
        $x_1_3 = {2e 64 6c 6c 00 62 69 74 44 65 66 65 6e 64 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pterodo_K_2147730715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pterodo.K"
        threat_id = "2147730715"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunProgram=\"hidcon:Cookies.cmd" ascii //weight: 1
        $x_1_2 = "RunProgram=\"hidcon:Wariable.cmd" ascii //weight: 1
        $x_1_3 = "RunProgram=\"hidcon:Wariables.cmd" ascii //weight: 1
        $x_1_4 = "RunProgram=\"hidcon:analise.cmd" ascii //weight: 1
        $x_1_5 = "RunProgram=\"hidcon:delsold.cmd" ascii //weight: 1
        $x_1_6 = "RunProgram=\"hidcon:downspreads.cmd" ascii //weight: 1
        $x_1_7 = "RunProgram=\"hidcon:icloud.cmd" ascii //weight: 1
        $x_1_8 = "RunProgram=\"hidcon:iclouds.cmd" ascii //weight: 1
        $x_1_9 = "RunProgram=\"hidcon:sosite.cmd" ascii //weight: 1
        $x_1_10 = "RunProgram=\"hidcon:updates.cmd" ascii //weight: 1
        $x_1_11 = "RunProgram=\"hidcon:windata.cmd" ascii //weight: 1
        $x_1_12 = "RunProgram=\"hidcon:winhost.cmd" ascii //weight: 1
        $x_20_13 = ";!@InstallEnd@!" ascii //weight: 20
        $x_20_14 = "GUIMode=\"2\"" ascii //weight: 20
        $x_20_15 = ";!@Install@!UTF-8!" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

