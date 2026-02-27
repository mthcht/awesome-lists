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

