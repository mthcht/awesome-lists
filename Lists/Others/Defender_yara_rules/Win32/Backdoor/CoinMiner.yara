rule Backdoor_Win32_CoinMiner_A_2147726370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CoinMiner.A"
        threat_id = "2147726370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MicrosoftCorporation\\Windows\\Helpers" ascii //weight: 1
        $x_1_2 = "\\MicrosoftCorporation\\Windows\\System32" ascii //weight: 1
        $x_1_3 = "\\WindowsAppCertification" ascii //weight: 1
        $x_2_4 = "\\{4FCEED6C-B7D9-405B-A844-C3DBF418BF87}" ascii //weight: 2
        $x_2_5 = "\\{CB28D9D3-6B5D-4AFA-BA37-B4AFAABF70B8}" ascii //weight: 2
        $x_1_6 = "/method/blacklist" ascii //weight: 1
        $x_1_7 = "/method/checkConnection" ascii //weight: 1
        $x_1_8 = "/method/cores" ascii //weight: 1
        $x_1_9 = "/method/delay" ascii //weight: 1
        $x_1_10 = "/method/install" ascii //weight: 1
        $x_1_11 = "/method/modules" ascii //weight: 1
        $x_1_12 = "/method/setOnline" ascii //weight: 1
        $x_1_13 = "/method/update" ascii //weight: 1
        $x_1_14 = "&hwid=" ascii //weight: 1
        $x_1_15 = "&platform=" ascii //weight: 1
        $x_1_16 = "&processor=" ascii //weight: 1
        $x_1_17 = "&profile=" ascii //weight: 1
        $x_1_18 = "&videocard=" ascii //weight: 1
        $x_2_19 = "delete_bot" ascii //weight: 2
        $x_1_20 = "install=done" ascii //weight: 1
        $x_2_21 = "restart_bot" ascii //weight: 2
        $x_1_22 = "{THREADS}" ascii //weight: 1
        $x_1_23 = "{EXE_PATH}" ascii //weight: 1
        $x_2_24 = "YXBpLmdvcGFuZWwucnU=" ascii //weight: 2
        $x_2_25 = "c3VjY2Vzcw==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

