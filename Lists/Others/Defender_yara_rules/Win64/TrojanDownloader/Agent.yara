rule TrojanDownloader_Win64_Agent_AMTB_2147963790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Agent!AMTB"
        threat_id = "2147963790"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "https://shieldguardvpn.pro/vpn/updates/stable.zip" ascii //weight: 6
        $x_6_2 = "Q(R(S(T1U1VDWEXEYEZE[E\\E]J^J_J`JaJbJcJdJeJfJgJhJ" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win64_Agent_AMTB_2147963790_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Agent!AMTB"
        threat_id = "2147963790"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "taskhostw.pages.dev" ascii //weight: 5
        $x_4_2 = "meterpreter" ascii //weight: 4
        $x_4_3 = "beacon" ascii //weight: 4
        $x_3_4 = "payload" ascii //weight: 3
        $x_3_5 = "inject" ascii //weight: 3
        $x_3_6 = "SeDebugPrivilege" ascii //weight: 3
        $x_1_7 = "shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

