rule Trojan_Win64_CryptoStealz_CG_2147954984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoStealz.CG!MTB"
        threat_id = "2147954984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "agent_idH" ascii //weight: 5
        $x_5_2 = "hostnameH" ascii //weight: 5
        $x_5_3 = "ip_addreH" ascii //weight: 5
        $x_5_4 = "locationH" ascii //weight: 5
        $x_5_5 = "cpu_modeH" ascii //weight: 5
        $x_5_6 = "pu_modeH" ascii //weight: 5
        $x_5_7 = "antiviruH" ascii //weight: 5
        $x_5_8 = "CurrentVersion\\Run" ascii //weight: 5
        $x_5_9 = "VBoxGuest.sys" ascii //weight: 5
        $x_5_10 = "sandbox_evasion.rs" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

