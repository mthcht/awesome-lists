rule Backdoor_Win32_Ofreayo_A_2147636707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ofreayo.A"
        threat_id = "2147636707"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofreayo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 44 18 ff 04 80 88 45 fa 8d 45 ?? 8a 55 fb 32 55 fa e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 f4 e8 ?? ?? ?? ?? 8b c7 e8 ?? ?? ?? ?? 3b f0 7c b6}  //weight: 5, accuracy: Low
        $x_1_2 = "<dourl>" ascii //weight: 1
        $x_1_3 = "<refurl1>" ascii //weight: 1
        $x_1_4 = "<sayfa1>" ascii //weight: 1
        $x_1_5 = "<gorunum>" ascii //weight: 1
        $x_1_6 = "superflood" ascii //weight: 1
        $x_1_7 = "httpflood" ascii //weight: 1
        $x_1_8 = "dnsflood" ascii //weight: 1
        $x_1_9 = "spread" ascii //weight: 1
        $x_1_10 = "File was Downloaded & Executed!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

