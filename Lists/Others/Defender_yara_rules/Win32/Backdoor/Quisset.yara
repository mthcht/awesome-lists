rule Backdoor_Win32_Quisset_A_2147622745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Quisset.A"
        threat_id = "2147622745"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Quisset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {05 80 d4 7d ee 6a 00 83 d1 02 68 80 96 98 00 51 50 e8}  //weight: 10, accuracy: High
        $x_2_2 = ".php?mac=" ascii //weight: 2
        $x_1_3 = ".deleted" ascii //weight: 1
        $x_1_4 = "delonly" ascii //weight: 1
        $x_1_5 = "starturl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Quisset_B_2147638327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Quisset.B"
        threat_id = "2147638327"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Quisset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AdSearch.DLL" ascii //weight: 2
        $x_2_2 = "http://www.ilikeclick.com/track/click.php?dts_code=" ascii //weight: 2
        $x_1_3 = "sysnotify.exe" ascii //weight: 1
        $x_3_4 = "http://cashbackmoa.co.kr/reward.php?name=%s&userid=%s&macaddr=%s&orgaddr=%s" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

